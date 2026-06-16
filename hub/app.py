import io
import os
import re
import shutil
import time
import uuid
import zipfile
import subprocess
import threading
import datetime
import psycopg2
import psycopg2.extras
from pathlib import Path
from urllib.parse import urlparse
import base64
import json
import urllib.request
import urllib.parse
from flask import Flask, render_template, request, jsonify, Response, send_from_directory, session, redirect, url_for
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024  # 500 MB
app.secret_key = os.environ.get('SECRET_KEY', 'dev-secret-change-me')

@app.errorhandler(413)
def too_large(_e):
    return jsonify({'error': 'File too large. Maximum upload size is 50 MB.'}), 413

@app.errorhandler(Exception)
def handle_exception(e):
    from werkzeug.exceptions import HTTPException
    if isinstance(e, HTTPException):
        return jsonify({'error': e.description}), e.code
    return jsonify({'error': str(e)}), 500

HUB_USERNAME = os.environ.get('HUB_USERNAME', 'admin')
HUB_PASSWORD = os.environ.get('HUB_PASSWORD', 'admin')
DATABASE_URL = os.environ.get('DATABASE_URL', '')

BASE_DIR = Path(__file__).parent
RESULTS_DIR = BASE_DIR / "results"
UPLOADS_DIR = BASE_DIR / "uploads"
RESULTS_DIR.mkdir(exist_ok=True)
UPLOADS_DIR.mkdir(exist_ok=True)

HOST_RESULTS_DIR = Path(os.environ.get('HOST_RESULTS_DIR', str(RESULTS_DIR)))

SONAR_HOST_URL   = os.environ.get('SONAR_HOST_URL',  'http://sonarqube:9000')
SONAR_PUBLIC_URL = os.environ.get('SONAR_PUBLIC_URL', 'http://localhost:9000')
SONAR_TOKEN      = os.environ.get('SONAR_TOKEN', '')
DOCKER_NETWORK   = os.environ.get('HUB_DOCKER_NETWORK', 'hub-net')

# In-memory store for live jobs (streaming needs it)
jobs = {}
slugs = {}  # slug → job_id

_db_lock = threading.Lock()


# ── Database ──────────────────────────────────────────────────────────────────

def get_conn():
    return psycopg2.connect(DATABASE_URL)


def init_db():
    with _db_lock, get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS jobs (
                    id          TEXT PRIMARY KEY,
                    slug        TEXT UNIQUE,
                    tool        TEXT NOT NULL,
                    status      TEXT NOT NULL,
                    target      TEXT,
                    scan_type   TEXT,
                    report_path TEXT,
                    started_at  TEXT
                )
            """)
        conn.commit()


def db_upsert(j):
    with _db_lock, get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO jobs (id, slug, tool, status, target, scan_type, report_path, started_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (id) DO UPDATE SET
                    slug        = EXCLUDED.slug,
                    status      = EXCLUDED.status,
                    target      = EXCLUDED.target,
                    report_path = EXCLUDED.report_path
            """, (
                j['id'], j.get('slug'), j['tool'], j['status'],
                j.get('url', j.get('file', '')),
                j.get('scan_type', ''),
                j.get('report_path'),
                j.get('started_at', ''),
            ))
        conn.commit()


def db_delete(job_id):
    with _db_lock, get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM jobs WHERE id = %s", (job_id,))
        conn.commit()


def load_db_jobs():
    """Load persisted jobs into memory on startup."""
    with get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT * FROM jobs ORDER BY started_at ASC")
            rows = cur.fetchall()
    for row in rows:
        job_id = row['id']
        slug = row['slug'] or job_id
        j = {
            'id': job_id,
            'slug': slug,
            'tool': row['tool'],
            'status': row['status'] if row['status'] not in ('running', 'starting') else 'error',
            'url': row['target'] if row['tool'] != 'jmeter' or '.' in (row['target'] or '') else '',
            'file': row['target'] if row['tool'] == 'jmeter' and (row['target'] or '').endswith('.jmx') else '',
            'scan_type': row['scan_type'] or '',
            'report_path': row['report_path'],
            'output': ['[HUB] (restored from database)'],
            'started_at': row['started_at'],
        }
        # Fix up target fields for jmeter file mode
        target = row['target'] or ''
        if row['tool'] == 'jmeter' and target.endswith('.jmx'):
            j['file'] = target
            j.pop('url', None)
        else:
            j['url'] = target
            j.pop('file', None)
        jobs[job_id] = j
        slugs[slug] = job_id
        # Jobs that were mid-run when container died are marked error
        if row['status'] in ('running', 'starting'):
            db_upsert(j)


# ── Slug helpers ──────────────────────────────────────────────────────────────

def make_slug(tool, target):
    try:
        hostname = urlparse(target if '://' in target else 'https://' + target).hostname or target
    except Exception:
        hostname = target or 'unknown'
    sanitized = re.sub(r'[^a-z0-9]+', '-', hostname.lower()).strip('-')
    return f"{tool}-{sanitized}"


def assign_slug(job_id, tool, target):
    base = make_slug(tool, target or 'unknown')
    slug, n = base, 2
    while slug in slugs:
        slug = f"{base}-{n}"
        n += 1
    slugs[slug] = job_id
    return slug


def job_by_slug(slug):
    job_id = slugs.get(slug)
    return jobs.get(job_id)


def docker_path(p: Path) -> str:
    return str(p).replace('\\', '/')


def spawn(fn):
    t = threading.Thread(target=fn, daemon=True)
    t.start()
    return t



def _zap_note(line):
    """Return an extra annotation line for notable ZAP output, or None."""
    l = line.lower()
    if 'job spider' in l and 'started' in l:
        return '[HUB] 🕷  Phase: Spider — crawling all links on the target…'
    if 'job passivescan-config' in l and 'started' in l:
        return '[HUB] 🔧 Phase: Configuring passive scan rules…'
    if 'job passivescan-wait' in l and 'started' in l:
        return '[HUB] 🔍 Phase: Passive scan — inspecting HTTP responses for vulnerabilities…'
    if 'job activescan' in l and 'started' in l:
        return '[HUB] ⚡ Phase: Active scan — probing for SQLi, XSS, RCE and more… (this takes a while)'
    if 'job report' in l and 'started' in l:
        return '[HUB] 📄 Phase: Generating HTML/JSON report…'
    if 'job spider' in l and 'finished' in l:
        return '[HUB] ✅ Spider finished.'
    if 'job passivescan-wait' in l and 'finished' in l:
        return '[HUB] ✅ Passive scan finished.'
    if 'job activescan' in l and 'finished' in l:
        return '[HUB] ✅ Active scan finished.'
    if 'starting zaproxy' in l or 'starting zap' in l:
        return '[HUB] 🚀 ZAP proxy starting up…'
    if 'total of' in l and 'alert' in l:
        return f'[HUB] 🚨 {line.strip()}'
    return None


def _jmeter_note(line):
    """Return a formatted summary line for JMeter summary output, or None."""
    stripped = line.strip()
    if not stripped.startswith('summary'):
        return None
    m = re.search(
        r'summary[+ =]+(\d+)\s+in\s+([\d:]+)\s*=\s*([\d.]+)/s\s+Err:\s+(\d+)',
        stripped,
    )
    if not m:
        return None
    total, duration, rate, errors = m.groups()
    err_part = f'⚠️  {errors} errors' if int(errors) > 0 else '✅ 0 errors'
    return f'[HUB] 📊 {total} requests · {duration} · {rate} req/s · {err_part}'


def _sonar_note(line):
    """Return an annotation line for notable sonar-scanner output, or None."""
    l = line.lower()
    if 'executing sensor' in l:
        m = re.search(r'executing sensor[:\s]+(.+)', line, re.IGNORECASE)
        if m:
            return f'[HUB] 🔍 Sensor: {m.group(1).strip()}'
    if 'analysis report generated' in l:
        return '[HUB] 📤 Uploading analysis to SonarQube…'
    if 'analysis report sent' in l or 'successfully uploaded' in l:
        return '[HUB] ✅ Analysis uploaded to SonarQube.'
    if 'quality gate status' in l:
        if 'passed' in l:
            return '[HUB] ✅ Quality Gate: PASSED'
        if 'failed' in l or 'error' in l:
            return '[HUB] ❌ Quality Gate: FAILED'
    if 'cloning into' in l:
        return '[HUB] 🔄 Cloning repository…'
    return None


# ── Auth ──────────────────────────────────────────────────────────────────────

@app.before_request
def require_login():
    open_endpoints = {'login', 'logout', 'static'}
    if request.endpoint in open_endpoints:
        return
    if not session.get('logged_in'):
        if request.path.startswith('/api/'):
            return jsonify({'error': 'Unauthorized'}), 401
        return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        if (request.form.get('username') == HUB_USERNAME and
                request.form.get('password') == HUB_PASSWORD):
            session['logged_in'] = True
            return redirect(url_for('index'))
        error = 'Invalid username or password.'
    return render_template('login.html', error=error)


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


@app.route('/')
def root():
    return redirect(url_for('index'))


@app.route('/hub')
def index():
    return render_template('index.html')


# ── ZAP ──────────────────────────────────────────────────────────────────────

@app.route('/api/zap/scan', methods=['POST'])
def zap_scan():
    data = request.get_json(force=True)
    url = (data.get('url') or '').strip()
    scan_type = data.get('scan_type', 'baseline')

    if not url:
        return jsonify({'error': 'URL is required'}), 400
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    job_id = uuid.uuid4().hex[:8]
    container_name = f'hub-zap-{job_id}'
    job_dir = RESULTS_DIR / f"zap_{job_id}"
    job_dir.mkdir()

    slug = assign_slug(job_id, 'zap', url)
    jobs[job_id] = {
        'id': job_id, 'slug': slug, 'tool': 'zap', 'status': 'starting',
        'url': url, 'scan_type': scan_type,
        'output': [], 'report_path': None,
        'container': container_name,
        'started_at': datetime.datetime.utcnow().isoformat() + 'Z',
    }
    db_upsert(jobs[job_id])

    def run():
        job = jobs[job_id]
        script = 'zap-baseline.py' if scan_type == 'baseline' else 'zap-full-scan.py'
        host_job_dir = HOST_RESULTS_DIR / f"zap_{job_id}"
        cmd = [
            'docker', 'run', '--rm',
            '--name', container_name,
            '--user', 'root',
            '-v', f'{docker_path(host_job_dir)}:/zap/wrk:rw',
            '-t', 'ghcr.io/zaproxy/zaproxy:stable',
            script, '-t', url, '-r', 'report.html', '-J', 'report.json', '-I',
        ]
        job['status'] = 'running'
        job['output'].append(f'[HUB] ZAP {scan_type} scan → {url}')
        job['output'].append('[HUB] (first run pulls the Docker image — may take 1–2 min)')
        job['output'].append('[HUB] 🔄 Initialising ZAP container…')
        db_upsert(job)
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, text=True, bufsize=1)
            job['proc'] = proc
            for raw in proc.stdout:
                line = raw.rstrip()
                job['output'].append(line)
                note = _zap_note(line)
                if note:
                    job['output'].append(note)
            proc.wait()
            if job['status'] == 'stopped':
                db_upsert(job)
                return
            report = job_dir / 'report.html'
            if report.exists():
                job['report_path'] = str(report)
                job['output'].append('[HUB] ✓ Report saved.')
            job['status'] = 'done'
            job['output'].append('[HUB] Scan finished.')
        except Exception as exc:
            if job['status'] != 'stopped':
                job['status'] = 'error'
                job['output'].append(f'[HUB] ERROR: {exc}')
        finally:
            db_upsert(job)
            job['output'].append('__DONE__')

    spawn(run)
    return jsonify({'job_id': job_id, 'slug': slug})


# ── JMeter ───────────────────────────────────────────────────────────────────

JMX_TEMPLATE = """<?xml version="1.0" encoding="UTF-8"?>
<jmeterTestPlan version="1.2" properties="5.0" jmeter="5.6.3">
  <hashTree>
    <TestPlan guiclass="TestPlanGui" testclass="TestPlan" testname="Hub Test">
      <elementProp name="TestPlan.user_defined_variables" elementType="Arguments"
                   guiclass="ArgumentsPanel" testclass="Arguments" testname="User Defined Variables">
        <collectionProp name="Arguments.arguments"/>
      </elementProp>
    </TestPlan>
    <hashTree>
      <ThreadGroup guiclass="ThreadGroupGui" testclass="ThreadGroup" testname="Users">
        <intProp name="ThreadGroup.num_threads">{threads}</intProp>
        <intProp name="ThreadGroup.ramp_time">{ramp_up}</intProp>
        <boolProp name="ThreadGroup.same_user_on_next_iteration">true</boolProp>
        <stringProp name="ThreadGroup.on_sample_error">continue</stringProp>
        <elementProp name="ThreadGroup.main_controller" elementType="LoopController"
                     guiclass="LoopControlPanel" testclass="LoopController" testname="Loop Controller">
          <boolProp name="LoopController.continue_forever">false</boolProp>
          <intProp name="LoopController.loops">{loops}</intProp>
        </elementProp>
      </ThreadGroup>
      <hashTree>
        <HTTPSamplerProxy guiclass="HttpTestSampleGui" testclass="HTTPSamplerProxy" testname="HTTP Request">
          <stringProp name="HTTPSampler.domain">{host}</stringProp>
          <stringProp name="HTTPSampler.port">{port}</stringProp>
          <stringProp name="HTTPSampler.protocol">{protocol}</stringProp>
          <stringProp name="HTTPSampler.path">{path}</stringProp>
          <stringProp name="HTTPSampler.method">GET</stringProp>
          <boolProp name="HTTPSampler.follow_redirects">true</boolProp>
          <boolProp name="HTTPSampler.auto_redirects">false</boolProp>
          <boolProp name="HTTPSampler.use_keepalive">true</boolProp>
        </HTTPSamplerProxy>
        <hashTree/>
        <ResultCollector guiclass="SummaryReport" testclass="ResultCollector" testname="Summary">
          <objProp>
            <name>saveConfig</name>
            <value class="SampleSaveConfiguration">
              <time>true</time><latency>true</latency><timestamp>true</timestamp>
              <success>true</success><label>true</label><code>true</code>
              <message>true</message><threadName>true</threadName><dataType>true</dataType>
              <encoding>false</encoding><assertions>true</assertions><subresults>true</subresults>
              <responseData>false</responseData><samplerData>false</samplerData>
              <xml>false</xml><fieldNames>true</fieldNames><bytes>true</bytes>
              <sentBytes>true</sentBytes><url>true</url><threadCounts>true</threadCounts>
              <idleTime>true</idleTime><connectTime>true</connectTime>
            </value>
          </objProp>
          <stringProp name="filename">/results/results.jtl</stringProp>
        </ResultCollector>
        <hashTree/>
      </hashTree>
    </hashTree>
  </hashTree>
</jmeterTestPlan>"""


@app.route('/api/jmeter/run', methods=['POST'])
def jmeter_run():
    mode = request.form.get('mode', 'url')
    test_mode = request.form.get('test_mode', 'quick')
    if test_mode == 'full':
        threads, ramp_up, loops = '50', '60', '3'
    elif test_mode == 'stress':
        threads, ramp_up, loops = '150', '30', '5'
    else:
        threads, ramp_up, loops = '10', '5', '1'

    job_id = uuid.uuid4().hex[:8]
    container_name = f'hub-jmeter-{job_id}'
    job_dir = RESULTS_DIR / f"jmeter_{job_id}"
    test_dir = job_dir / "test"
    results_dir = job_dir / "results"
    for d in (test_dir, results_dir):
        d.mkdir(parents=True)

    jobs[job_id] = {
        'id': job_id, 'slug': None, 'tool': 'jmeter', 'status': 'starting',
        'scan_type': test_mode,
        'output': [], 'report_path': None,
        'container': container_name,
        'started_at': datetime.datetime.utcnow().isoformat() + 'Z',
    }

    if mode == 'url':
        url = (request.form.get('url') or '').strip()
        if not url:
            return jsonify({'error': 'URL is required'}), 400
        raw = url if '://' in url else 'https://' + url
        parsed = urlparse(raw)
        jmx = JMX_TEMPLATE.format(
            host=parsed.hostname or url,
            port=str(parsed.port) if parsed.port else '',
            protocol=parsed.scheme or 'https',
            path=parsed.path or '/',
            threads=threads, ramp_up=ramp_up, loops=loops,
        )
        jmx_file = test_dir / 'test.jmx'
        jmx_file.write_text(jmx, encoding='utf-8')
        jobs[job_id]['url'] = url
        jobs[job_id]['slug'] = assign_slug(job_id, 'jmeter', url)
    else:
        if 'jmx_file' not in request.files:
            return jsonify({'error': 'No file uploaded'}), 400
        f = request.files['jmx_file']
        if not f.filename or not f.filename.lower().endswith('.jmx'):
            return jsonify({'error': 'Only .jmx files allowed'}), 400
        fname = secure_filename(f.filename)
        jmx_file = test_dir / fname
        f.save(jmx_file)
        jobs[job_id]['file'] = fname
        jobs[job_id]['slug'] = assign_slug(job_id, 'jmeter', fname)

    db_upsert(jobs[job_id])

    def run():
        job = jobs[job_id]
        host_test_dir    = HOST_RESULTS_DIR / f"jmeter_{job_id}" / "test"
        host_results_dir = HOST_RESULTS_DIR / f"jmeter_{job_id}" / "results"
        cmd = [
            'docker', 'run', '--rm',
            '--name', container_name,
            '-v', f'{docker_path(host_test_dir)}:/test:ro',
            '-v', f'{docker_path(host_results_dir)}:/results:rw',
            'justb4/jmeter',
            '-n', '-t', f'/test/{jmx_file.name}',
            '-l', '/results/results.jtl',
            '-e', '-o', '/results/report',
        ]
        job['status'] = 'running'
        ttype = 'Quick (10 users)' if test_mode == 'quick' else 'Stress (150 users)' if test_mode == 'stress' else 'Full (50 users)'
        job['output'].append(f'[HUB] JMeter {ttype} test → {mode} mode')
        job['output'].append('[HUB] (first run pulls the Docker image — may take 1–2 min)')
        job['output'].append('[HUB] 🔄 Initialising JMeter container…')
        db_upsert(job)
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, text=True, bufsize=1)
            job['proc'] = proc
            for raw in proc.stdout:
                line = raw.rstrip()
                job['output'].append(line)
                note = _jmeter_note(line)
                if note:
                    job['output'].append(note)
            proc.wait()
            if job['status'] == 'stopped':
                db_upsert(job)
                return
            report = results_dir / 'report' / 'index.html'
            if report.exists():
                job['report_path'] = str(results_dir / 'report')
                job['output'].append('[HUB] ✓ HTML report ready.')
            elif (results_dir / 'results.jtl').exists():
                job['output'].append('[HUB] ✓ results.jtl saved (no HTML report).')
            job['status'] = 'done'
            job['output'].append('[HUB] Test finished.')
        except Exception as exc:
            if job['status'] != 'stopped':
                job['status'] = 'error'
                job['output'].append(f'[HUB] ERROR: {exc}')
        finally:
            db_upsert(job)
            job['output'].append('__DONE__')

    spawn(run)
    return jsonify({'job_id': job_id, 'slug': jobs[job_id]['slug']})


# ── SonarQube ────────────────────────────────────────────────────────────────

@app.route('/api/sonar/scan', methods=['POST'])
def sonar_scan():
    mode      = request.form.get('mode', 'git')
    repo_url  = (request.form.get('repo_url') or '').strip()
    branch    = (request.form.get('branch') or 'main').strip() or 'main'
    git_token = (request.form.get('git_token') or '').strip()

    if not SONAR_TOKEN:
        return jsonify({'error': 'SONAR_TOKEN is not configured. '
                        'Visit http://localhost:9000, generate a global analysis token, '
                        'and add SONAR_TOKEN=<token> to your .env file and restart.'}), 503

    if mode == 'git':
        if not repo_url:
            return jsonify({'error': 'Repository URL is required'}), 400
        target = repo_url
    else:
        if 'zip_file' not in request.files:
            return jsonify({'error': 'No ZIP file uploaded'}), 400
        zf_upload = request.files['zip_file']
        if not zf_upload.filename or not zf_upload.filename.lower().endswith('.zip'):
            return jsonify({'error': 'Only .zip files are allowed'}), 400
        target = secure_filename(zf_upload.filename)

    # Derive a human-readable project name from the repo URL or ZIP filename
    if mode == 'zip':
        raw_name = os.path.splitext(os.path.basename(target))[0]
    else:
        _path = urlparse(target).path.rstrip('/')
        raw_name = _path.split('/')[-1]
        if raw_name.lower().endswith('.git'):
            raw_name = raw_name[:-4]
    raw_name = raw_name or 'scan'
    # SonarQube project key: alphanumeric + hyphens/dots/underscores/colons
    project_key  = re.sub(r'[^a-z0-9._:-]+', '-', raw_name.lower()).strip('-') or 'scan'
    project_name = raw_name  # display name keeps original casing

    job_id  = uuid.uuid4().hex[:8]
    job_dir = RESULTS_DIR / f'sonar_{job_id}'
    code_dir    = job_dir / 'code'
    code_dir.mkdir(parents=True)

    zip_path = None
    if mode == 'zip':
        zip_path = job_dir / target
        zf_upload.save(zip_path)

    slug = assign_slug(job_id, 'sonar', target)
    jobs[job_id] = {
        'id': job_id, 'slug': slug, 'tool': 'sonar', 'status': 'starting',
        'url': target, 'scan_type': '',
        'output': [], 'report_path': None,
        'container': f'hub-sonar-{job_id}',
        'started_at': datetime.datetime.utcnow().isoformat() + 'Z',
        'project_key': project_key,
    }
    db_upsert(jobs[job_id])

    # Build git auth header (avoids URL-encoding issues with special chars in tokens)
    git_auth_header = None
    if mode == 'git' and git_token:
        parsed   = urlparse(repo_url)
        hostname = (parsed.hostname or '').lower()
        if 'bitbucket.org' in hostname:
            username = 'x-token-auth'
        elif 'gitlab.' in hostname:
            username = 'oauth2'
        else:
            username = 'oauth2'   # works for GitHub PATs and most other hosts
        raw = base64.b64encode(f'{username}:{git_token}'.encode()).decode()
        git_auth_header = f'Authorization: Basic {raw}'

    def run():
        job = jobs[job_id]
        host_code_dir = HOST_RESULTS_DIR / f'sonar_{job_id}' / 'code'

        job['status'] = 'running'
        job['output'].append(f'[HUB] SonarQube scan → {target}')
        job['output'].append('[HUB] (first run pulls Docker images — may take a moment)')
        db_upsert(job)

        try:
            if mode == 'zip':
                # ── Step 1 (ZIP): Extract archive ──────────────────────────
                job['output'].append('[HUB] 📦 Extracting uploaded archive…')
                with zipfile.ZipFile(zip_path, 'r') as zf:
                    zf.extractall(code_dir)
                job['output'].append('[HUB] ✅ Archive extracted.')
            else:
                # ── Step 1 (Git): Clone ────────────────────────────────────
                clone_name = f'hub-git-{job_id}'
                job['container'] = clone_name
                job['output'].append(f'[HUB] 🔄 Cloning {repo_url} (branch: {branch})…')
                git_cmd = ['docker', 'run', '--rm', '--name', clone_name,
                           '-v', f'{docker_path(host_code_dir)}:/repo',
                           'alpine/git']
                if git_auth_header:
                    git_cmd += ['-c', f'http.extraHeader={git_auth_header}']
                git_cmd += ['clone', '--depth=1', '--branch', branch, repo_url, '/repo']
                proc_git = subprocess.Popen(
                    git_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                    text=True, bufsize=1,
                )
                for raw in proc_git.stdout:
                    line = raw.rstrip()
                    job['output'].append(line)
                proc_git.wait()

                if job['status'] == 'stopped':
                    db_upsert(job)
                    return

                if proc_git.returncode != 0:
                    job['status'] = 'error'
                    job['output'].append('[HUB] ERROR: Failed to clone repository. '
                                         'Check the URL, branch name, and access token.')
                    return

            if mode == 'git':
                job['output'].append('[HUB] ✅ Repository cloned successfully.')
            job['output'].append('[HUB] 🔍 Phase: Running SonarQube analysis…')

            # ── Step 2: Sonar-scanner ──────────────────────────────────────
            scanner_name = f'hub-sonar-{job_id}'
            job['container'] = scanner_name
            scanner_cmd = [
                'docker', 'run', '--rm',
                '--name', scanner_name,
                '--network', DOCKER_NETWORK,
                '-v', f'{docker_path(host_code_dir)}:/usr/src',
                '-e', f'SONAR_TOKEN={SONAR_TOKEN}',
                '-e', f'SONAR_HOST_URL={SONAR_HOST_URL}',
                'sonarsource/sonar-scanner-cli',
                f'-Dsonar.projectKey={project_key}',
                f'-Dsonar.projectName={project_name}',
                '-Dsonar.sources=.',
                '-Dsonar.scm.disabled=true',
            ]
            proc_scan = subprocess.Popen(
                scanner_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1,
            )
            job['proc'] = proc_scan
            for raw in proc_scan.stdout:
                line = raw.rstrip()
                job['output'].append(line)
                note = _sonar_note(line)
                if note:
                    job['output'].append(note)
            proc_scan.wait()

            if job['status'] == 'stopped':
                db_upsert(job)
                return

            if proc_scan.returncode != 0:
                job['status'] = 'error'
                job['output'].append('[HUB] ERROR: SonarQube analysis failed.')
                return

            job['output'].append('[HUB] ✅ Analysis complete. Fetching quality gate…')

            # ── Step 3: Poll quality gate ──────────────────────────────────
            # SonarQube analysis tokens use HTTP Basic auth (token:empty-password),
            # not Bearer. The CE task also needs a few seconds to process first.
            qg_url    = (f'{SONAR_HOST_URL}/api/qualitygates/project_status'
                         f'?projectKey={project_key}')
            token_b64 = base64.b64encode(f'{SONAR_TOKEN}:'.encode()).decode()
            qg_status = 'NONE'
            time.sleep(3)  # give CE task a head-start
            for attempt in range(12):
                try:
                    req = urllib.request.Request(
                        qg_url,
                        headers={'Authorization': f'Basic {token_b64}'},
                    )
                    with urllib.request.urlopen(req, timeout=10) as resp:
                        body = json.loads(resp.read().decode())
                        qg_status = body.get('projectStatus', {}).get('status', 'NONE')
                    if qg_status != 'NONE':
                        break
                    # Status is NONE → CE task not finished yet, keep waiting
                    job['output'].append(f'[HUB] ⏳ Waiting for quality gate… ({attempt + 1}/12)')
                    time.sleep(5)
                except Exception as exc:
                    job['output'].append(f'[HUB] ⏳ Waiting for quality gate… ({attempt + 1}/12): {exc}')
                    time.sleep(5)

            dashboard_url = f'{SONAR_PUBLIC_URL}/dashboard?id={project_key}'
            job['scan_type']   = qg_status
            job['report_path'] = dashboard_url

            if qg_status == 'OK':
                job['output'].append('[HUB] ✅ Quality Gate: PASSED')
            elif qg_status == 'ERROR':
                job['output'].append('[HUB] ❌ Quality Gate: FAILED')
            elif qg_status == 'WARN':
                job['output'].append('[HUB] ⚠️  Quality Gate: WARNING')
            else:
                job['output'].append(f'[HUB] Quality Gate: {qg_status}')

            job['output'].append(f'[HUB] 📄 Dashboard → {dashboard_url}')

            # ── Step 4: Set project visibility to private ──────────────────
            try:
                vis_data = urllib.parse.urlencode(
                    {'project': project_key, 'visibility': 'private'}
                ).encode()
                vis_req = urllib.request.Request(
                    f'{SONAR_HOST_URL}/api/projects/update_visibility',
                    data=vis_data, method='POST',
                )
                vis_req.add_header('Authorization', f'Basic {token_b64}')
                urllib.request.urlopen(vis_req, timeout=10)
                job['output'].append('[HUB] 🔒 Project visibility set to private.')
            except Exception:
                pass  # requires admin permission; silently skip

            job['status'] = 'done'
            job['output'].append('[HUB] Scan finished.')

        except Exception as exc:
            if job['status'] != 'stopped':
                job['status'] = 'error'
                job['output'].append(f'[HUB] ERROR: {exc}')
        finally:
            db_upsert(job)
            job['output'].append('__DONE__')

    spawn(run)
    return jsonify({'job_id': job_id, 'slug': slug})


# ── Stop ──────────────────────────────────────────────────────────────────────

@app.route('/api/jobs/<job_id>/stop', methods=['POST'])
def stop_job(job_id):
    if job_id not in jobs:
        return jsonify({'error': 'Not found'}), 404
    j = jobs[job_id]
    if j['status'] != 'running':
        return jsonify({'error': 'Job is not running'}), 400
    j['status'] = 'stopped'
    j['output'].append('[HUB] Stop requested by user...')
    container = j.get('container')
    if container:
        subprocess.run(['docker', 'stop', container], capture_output=True)
    db_upsert(j)
    return jsonify({'ok': True})


# ── Streaming ─────────────────────────────────────────────────────────────────

@app.route('/api/stream/<job_id>')
def stream(job_id):
    def generate():
        for _ in range(60):
            if job_id in jobs:
                break
            time.sleep(0.1)
        if job_id not in jobs:
            yield 'data: [HUB] Job not found.\n\ndata: __DONE__\n\n'
            return
        job = jobs[job_id]
        sent = 0
        while True:
            while sent < len(job['output']):
                line = job['output'][sent]
                sent += 1
                yield f'data: {line}\n\n'
                if line == '__DONE__':
                    return
            time.sleep(0.15)

    return Response(generate(), mimetype='text/event-stream',
                    headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'})


@app.route('/api/status/<job_id>')
def job_status(job_id):
    if job_id not in jobs:
        return jsonify({'error': 'Not found'}), 404
    j = jobs[job_id]
    resp = {
        'status': j['status'],
        'has_report': j['report_path'] is not None,
        'slug': j.get('slug', j['id']),
        'scan_type': j.get('scan_type', ''),
    }
    if j.get('tool') == 'sonar' and j.get('report_path'):
        resp['report_url'] = j['report_path']
    return jsonify(resp)


@app.route('/api/jobs')
def list_jobs():
    return jsonify([
        {
            'id': j['id'],
            'slug': j.get('slug', j['id']),
            'tool': j['tool'],
            'status': j['status'],
            'has_report': j['report_path'] is not None,
            'target': j.get('url', j.get('file', '')),
            'scan_type': j.get('scan_type', ''),
            'started_at': j.get('started_at', ''),
        }
        for j in sorted(jobs.values(), key=lambda x: x.get('started_at', ''), reverse=True)
    ])


# ── Downloads ─────────────────────────────────────────────────────────────────

@app.route('/downloads')
def downloads_index():
    completed = [
        {'id': j['id'], 'slug': j.get('slug', j['id']), 'tool': j['tool'], 'status': j['status'],
         'has_report': j['report_path'] is not None,
         'effective_status': j['status'] if j['report_path'] is not None or j['status'] in ('stopped', 'error') else 'done',
         'target': j.get('url', j.get('file', '')),
         'scan_type': j.get('scan_type', ''),
         'started_at': j.get('started_at', '')}
        for j in jobs.values()
        if j['status'] in ('done', 'error', 'stopped')
    ]
    return render_template('downloads.html', jobs=completed)


@app.route('/downloads/<slug>')
def get_report(slug):
    j = job_by_slug(slug)
    if not j:
        return jsonify({'error': 'Not found'}), 404
    if not j['report_path']:
        return jsonify({'error': 'No report available'}), 404
    if j['tool'] == 'sonar':
        return redirect(j['report_path'])
    p = Path(j['report_path'])
    if j['tool'] == 'zap':
        return send_from_directory(p.parent, p.name)
    return redirect(f'/downloads/{slug}/')


@app.route('/downloads/<slug>/')
def get_report_index(slug):
    j = job_by_slug(slug)
    if not j:
        return jsonify({'error': 'Not found'}), 404
    if not j['report_path']:
        return jsonify({'error': 'No report available'}), 404
    return send_from_directory(Path(j['report_path']), 'index.html')


@app.route('/downloads/<slug>/<path:filename>')
def get_report_asset(slug, filename):
    j = job_by_slug(slug)
    if not j or not j['report_path']:
        return jsonify({'error': 'Not found'}), 404
    return send_from_directory(Path(j['report_path']), filename)


@app.route('/downloads/<slug>/export')
def download_report(slug):
    j = job_by_slug(slug)
    if not j:
        return jsonify({'error': 'Not found'}), 404
    if not j['report_path']:
        return jsonify({'error': 'No report available'}), 404
    if j['tool'] == 'sonar':
        return redirect(j['report_path'])
    if j['tool'] == 'zap':
        p = Path(j['report_path'])
        return send_from_directory(p.parent, p.name, as_attachment=True,
                                   download_name=f"{slug}.html")
    else:
        report_dir = Path(j['report_path'])
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zf:
            for f in report_dir.rglob('*'):
                if f.is_file():
                    zf.write(f, f.relative_to(report_dir))
        buf.seek(0)
        return Response(buf.read(), mimetype='application/zip',
                        headers={'Content-Disposition': f'attachment; filename="{slug}.zip"'})


@app.route('/downloads/<slug>/delete', methods=['POST'])
def delete_report(slug):
    j = job_by_slug(slug)
    if not j:
        return jsonify({'error': 'Not found'}), 404
    job_id = j['id']
    job_dir = RESULTS_DIR / f"{j['tool']}_{job_id}"
    if job_dir.exists():
        shutil.rmtree(job_dir, ignore_errors=True)
    db_delete(job_id)
    slugs.pop(slug, None)
    jobs.pop(job_id, None)
    return jsonify({'ok': True})


if __name__ == '__main__':
    init_db()
    load_db_jobs()
    print('\n  Hub running at http://localhost:5000\n')
    app.run(debug=False, host='0.0.0.0', port=5000, threaded=True)
