# Security & Testing Hub

A Dockerized web application that lets you run **OWASP ZAP** security scans, **Apache JMeter** load tests, and **SonarQube** code analysis — with a real-time log stream, per-scan report links, and a PostgreSQL-backed job history.

---

## Features

- **OWASP ZAP** — Baseline (passive) and Full (active) security scans
- **Apache JMeter** — Quick / Full / Stress load tests via URL or uploaded `.jmx` plan
- **SonarQube** — Static code analysis from Git repositories or uploaded `.zip` archives
- Real-time SSE log streaming with annotated phase markers
- Per-URL log tabs when scanning multiple URLs in a queue
- Slug-based report URLs (e.g. `/downloads/zap-example-com`)
- PostgreSQL persistence — jobs survive `docker-compose restart`
- Bulk select & delete on the Downloads page
- Session-based authentication

---

## Requirements

- Docker & Docker Compose
- The host must expose `/var/run/docker.sock` (Docker-out-of-Docker)

---

## Setup

### 1. Clone the repository

```bash
git clone <repo-url>
cd <repo-directory>
```

### 2. Create the `.env` file

Copy the example below and fill in the values for your environment:

```env
# Absolute paths on the HOST machine where results and uploads are stored.
# These are bind-mounted into the hub container AND passed to sibling ZAP/JMeter containers.
HOST_RESULTS_DIR=/path/to/results
HOST_UPLOADS_DIR=/path/to/uploads

# Hub login credentials
HUB_USERNAME=admin
HUB_PASSWORD=admin

# Flask secret key — generate with: openssl rand -hex 32
SECRET_KEY=your-secret-key

# PostgreSQL password
DB_PASSWORD=your-db-password

# SonarQube
SONAR_TOKEN=your-sonarqube-token
SONAR_PUBLIC_URL=http://localhost:9000/sonar
SONAR_DB_PASSWORD=your-sonarqube-db-password
```

Create the result directories before first run:

```bash
mkdir -p /path/to/results /path/to/uploads
```

### 3. Start the stack

```bash
docker-compose up -d --build
```

The hub will be available at **http://localhost:5000/hub**.
SonarQube will be available at **http://localhost:9000/sonar**.

Default logins:

- Hub: `admin` / `admin`
- SonarQube: `admin` / `admin`

---

## Configuration

| Variable | Description |
|---|---|
| `HOST_RESULTS_DIR` | Absolute host path for scan results |
| `HOST_UPLOADS_DIR` | Absolute host path for `.jmx` uploads |
| `HUB_USERNAME` | Login username |
| `HUB_PASSWORD` | Login password |
| `SECRET_KEY` | Flask session secret (use `openssl rand -hex 32`) |
| `DB_PASSWORD` | PostgreSQL password |
| `SONAR_TOKEN` | SonarQube user token used by scanner jobs |
| `SONAR_PUBLIC_URL` | Browser-facing SonarQube URL used for dashboard links |
| `SONAR_DB_PASSWORD` | SonarQube PostgreSQL password |

---

## Project Structure

```
.
├── docker-compose.yml       # Defines hub + PostgreSQL services
├── .env                     # Environment variables (not committed)
└── hub/
    ├── Dockerfile
    ├── app.py               # Flask application
    ├── requirements.txt
    ├── .dockerignore
    ├── static/
    │   └── favicon.png
    ├── templates/
    │   ├── index.html       # Main hub page
    │   ├── downloads.html   # Reports list
    │   └── login.html
    ├── results/             # Scan output (bind-mounted from host)
    └── uploads/             # JMX file uploads (bind-mounted from host)
```

---

## Usage

### ZAP Security Scan

1. Navigate to **http://localhost:5000/hub**
2. Enter one or more target URLs (use **Add more** for a queue)
3. Select **Baseline** (fast, passive) or **Full Scan** (active, thorough)
4. Click **Start Scan** — logs stream in real time
5. When finished, click **View ZAP Report** or go to **Downloads**

### JMeter Load Test

1. Choose **From URL** or **Upload .jmx**
2. Select test type:
   - **Quick** — 10 users, ~10 seconds
   - **Full** — 50 users, ~5–8 minutes
   - **Stress** — 150 users, ~15 minutes
3. Click **Start Test**

### SonarQube Code Analysis

1. Create a SonarQube token from **http://localhost:9000/sonar** and set it as `SONAR_TOKEN` in `.env`
2. In the hub, choose **Git repository** or **ZIP archive**
3. For Git scans, enter the repository URL and branch; add a Git token if the repository is private
4. For ZIP scans, upload a `.zip` containing the source code
5. Click **Start Analysis**
6. When finished, open the SonarQube dashboard link from the hub or Downloads page

### Multiple URLs (Queue)

Enter the first URL, click **Add more** to add additional inputs. Each URL runs sequentially after the previous one finishes. Use the tab buttons above the log to switch between completed URL logs.

---

## Architecture

```
Browser
  │
  ▼
Flask Hub (port 5000)
  │  ├── Streams logs via SSE
  │  ├── Serves ZAP/JMeter HTML reports
  │  ├── Links SonarQube dashboards
  │  └── Persists jobs to PostgreSQL
  │
  ├── Spawns ──▶ ZAP container (sibling via Docker socket)
  ├── Spawns ──▶ JMeter container (sibling via Docker socket)
  └── Spawns ──▶ Sonar scanner container (sibling via Docker socket)

PostgreSQL databases
  ├── Hub job history
  └── SonarQube data
```

The hub uses **Docker-out-of-Docker (DooD)**: it mounts the host's Docker socket (`/var/run/docker.sock`) and spawns ZAP, JMeter, and Sonar scanner containers as siblings. The `HOST_RESULTS_DIR` variable ensures sibling containers mount the same results directory as the hub.

---

## Production Deployment

1. Set all `.env` variables to production values
2. Generate a strong `SECRET_KEY`: `openssl rand -hex 32`
3. Use strong passwords for `HUB_PASSWORD`, `DB_PASSWORD`, and `SONAR_DB_PASSWORD`
4. Put the hub behind a reverse proxy (nginx/Caddy) with HTTPS
5. Add `.env` to `.gitignore` — never commit credentials

---

## Services

| Service | Image | Description |
|---|---|---|
| `hub` | Built from `./hub` | Flask web application |
| `db` | `postgres:16-alpine` | Job persistence |
| `sonarqube` | `sonarqube:community` | Static code analysis dashboard |
| `sonar-db` | `postgres:16-alpine` | SonarQube database |
| ZAP | `ghcr.io/zaproxy/zaproxy:stable` | Spawned on demand |
| JMeter | `justb4/jmeter` | Spawned on demand |
