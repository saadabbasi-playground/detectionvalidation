# detection-validator

Multi-SIEM detection validation platform. Validate detection rules against live
or synthetic attack telemetry, map coverage to MITRE ATT\&CK, and surface gaps.

> **Apple Silicon (M1/M2/M3/M4):** fully supported. See the
> [Apple Silicon setup guide](#apple-silicon-m1m2m3m4) below.

```
./dv up lab --siem opensearch
./dv validate --rules ./detections/ --siem opensearch --format sarif
./dv report --format cli
```

## Prerequisites

| Requirement | Version |
|---|---|
| Docker Desktop | ≥ 4.27 (includes compose v2 + buildx) |
| Python | 3.12 (host dev only) |
| uv | latest (`brew install uv`) |

```bash
./dv doctor          # verify everything before you start
```

---

## Apple Silicon (M1/M2/M3/M4)

**Tested on:** MacBook Pro M3, macOS Sequoia 15 — all core services confirmed healthy.

### What works natively on ARM

| Component | Image | ARM64 status |
|---|---|---|
| OpenSearch | `opensearchproject/opensearch:3.x` | ✅ tested |
| OpenSearch Dashboards | `opensearchproject/opensearch-dashboards:3.x` | ✅ tested |
| Redis | `redis:7-alpine` | ✅ tested |
| Splunk HEC mock | `detectval/splunk-hec` (Python) | ✅ tested |
| Elastic / Kibana | `docker.elastic.co/…:8.x` | ✅ multi-arch (not tested locally) |
| Wazuh | `wazuh/wazuh-manager:4.x` | ✅ multi-arch (not tested locally) |
| Grafana | `grafana/grafana:11.x` | ✅ multi-arch (not tested locally) |
| Lab containers (attacker, linux-victim, win-emulator) | `detectval/*` | ✅ built for linux/arm64 |

| Component | ARM64 status | Alternative |
|---|---|---|
| Splunk Enterprise | ❌ `splunk/splunk` is amd64-only | Use `--siem opensearch` or the HEC mock |
| Windows victim container | ❌ requires Windows daemon | Use `win-emulator` (default on ARM) |

### Step-by-step setup on Apple Silicon

**1. Install Docker Desktop for Mac (Apple Silicon)**

Download the **Apple Chip** installer from [docker.com/products/docker-desktop](https://www.docker.com/products/docker-desktop/).
Enable "Use Rosetta for x86/amd64 emulation" in **Settings → General** — this is
required if you ever want to run amd64-only images under emulation.

**2. Install Python 3.12 and uv**

```bash
brew install python@3.12 uv
```

**3. Clone and set up the project**

```bash
git clone <repo-url> detection-validator
cd detection-validator

# Create and populate the Python virtual environment
uv venv
uv pip install -e ".[dev]"
```

**4. Set required environment variables**

```bash
cp .env.example .env          # if present, or create manually
# Minimum required:
export OPENSEARCH_INITIAL_ADMIN_PASSWORD="DetectVal123!"
```

Or add them to a `.env` file in the project root — docker compose picks them up automatically.

**5. Start the recommended ARM stack (OpenSearch)**

```bash
./dv up lab --siem opensearch --profile tiny
```

This starts: OpenSearch · OpenSearch Dashboards · Redis · Vector shipper · lab containers.
The `tiny` profile uses ≤ 1 GB RAM per service and is the right choice for a 16 GB MacBook.

**6. Confirm all containers are healthy**

```bash
docker ps --format "table {{.Names}}\t{{.Status}}"
```

Expected output after ~60 s:

```
NAMES                             STATUS
dv-opensearch                     Up X minutes (healthy)
dv-opensearch-dashboards          Up X minutes (healthy)
dv-redis                          Up X minutes (healthy)
dv-vector                         Up X minutes (healthy)
detectval-splunk                  Up X minutes (healthy)
```

**7. Run the Python CLI**

```bash
source .venv/bin/activate

# Parse your detections
dv ingest detections/ -o canonical.jsonl

# Map to ATT&CK (downloads STIX bundle on first run ~30 s)
dv intel update --source attack
dv map -i canonical.jsonl -o mapped.jsonl --mode hybrid

# Check CVE coverage
dv intel update --source cve
dv cve-coverage --cve CVE-2021-44228 --detections mapped.jsonl
```

**8. Open the dashboards**

| Service | URL | Credentials |
|---|---|---|
| OpenSearch Dashboards | http://localhost:5601 | admin / `$OPENSEARCH_INITIAL_ADMIN_PASSWORD` |
| Splunk HEC mock UI | http://localhost:8000 | (no login) |

### Using Splunk on Apple Silicon

The official `splunk/splunk` image is amd64-only. Two alternatives:

**Option A — Splunk HEC mock (included, no license needed)**

The project ships `detectval/splunk-hec`, a lightweight Python server that
implements the HEC ingest API, a basic search endpoint, and a dark-themed
dashboard. It runs natively on ARM and requires no Splunk license.

```bash
docker run -d --name detectval-splunk --network detectval-lab \
  -p 8000:8088 -p 8088:8088 \
  -v splunk-data:/data \
  -e SPLUNK_HEC_TOKEN="detectval-hec-token" \
  detectval/splunk-hec:latest
```

**Option B — Splunk Enterprise via Rosetta 2 (emulation)**

Docker Desktop can run amd64 images under Rosetta 2. Performance is noticeably
slower (2–3× startup time) but it works for light validation use cases.

```bash
# Ensure Rosetta emulation is on in Docker Desktop → Settings → General
./dv up lab --siem splunk --profile tiny
```

> Expect ~3–5 minutes for Splunk to reach healthy on M-series under emulation.
> Use `--siem opensearch` for day-to-day work and reserve Splunk for
> cross-SIEM comparison runs.

### Troubleshooting on Apple Silicon

**`exec format error` on container start**

A container was built for amd64 and Rosetta emulation is not enabled.
Go to Docker Desktop → Settings → General → enable "Use Rosetta for x86/amd64 emulation".

**OpenSearch fails with `max virtual memory areas vm.max_map_count [65530] is too low`**

```bash
# Increase the limit inside the Docker Desktop VM (persists until Docker Desktop restart)
docker run --rm --privileged alpine sysctl -w vm.max_map_count=262144
```

**Out of memory / containers restarting**

Switch to the `tiny` profile and raise Docker Desktop's memory limit:
Docker Desktop → Settings → Resources → Memory → set to ≥ 6 GB.

```bash
./dv up lab --siem opensearch --profile tiny
```

**`dv` command not found**

Make sure the venv is active:
```bash
source .venv/bin/activate
which dv   # should point inside .venv/bin/
```

---

## Quick start (all platforms)

```bash
# 1. Start the full lab (ARM default: opensearch)
./dv up lab --siem opensearch --profile standard

# 2. Parse and ingest your detection rules
dv ingest detections/ -o canonical.jsonl

# 3. Map to ATT&CK
dv map -i canonical.jsonl -o mapped.jsonl --mode hybrid

# 4. Generate a SARIF report for GitHub Code Scanning
./dv report --format sarif --output results.sarif
```

## Architecture

```
┌─ core ──────────────────────────────────────────────────────────┐
│  detection_validator  (FastAPI + Celery)                         │
│  parsers ▸ normalizer ▸ validator ▸ coverage ▸ reporters        │
└──────────────────────────────────────────────────────────────────┘
        │                    │                    │
┌─ lab ─┴──────┐    ┌────────┴──────┐    ┌───────┴──────────────┐
│  attacker    │    │  linux-victim │    │  atomic-runner        │
│  (Kali-slim) │    │  (auditd +    │    │  (invoke-atomicredteam│
│  nuclei,ART  │    │   Sysmon,Falco│    │   + ART library)     │
└──────────────┘    └───────────────┘    └──────────────────────┘
        │
┌─ siem ─┴──────────────────────────────────────────────────────┐
│  opensearch / elastic / splunk / sentinel / chronicle / wazuh  │
│  + vector (shipper)  + grafana (dashboards)                    │
└────────────────────────────────────────────────────────────────┘
```

## Resource profiles

```bash
./dv up lab --profile tiny      # ≤1 GB RAM per service — Pi / free CI / M-series
./dv up lab --profile standard  # 4 GB RAM — dev workstation
./dv up lab --profile full      # 8 GB+ RAM — all services
```

## Composable SIEM

```bash
# Single SIEM (recommended on Apple Silicon)
./dv up lab --siem opensearch

# Dual-write (amd64 or Rosetta emulation required for Splunk)
./dv up lab --siem splunk,opensearch
```

## GitHub Action

Drop into your detection-as-code repo:

```yaml
jobs:
  validate:
    uses: detection-validator/detection-validator/.github/workflows/detection-validation.yml@main
    with:
      rules-path: detections/
      siem: opensearch
      output-format: sarif
```

Or use the composite action directly:

```yaml
- uses: detection-validator/detection-validator/actions/validate@main
  with:
    rules-path: detections/
    siem: opensearch
```

## GitHub Codespaces

Click **Code → Codespaces → Create** — Docker-in-Docker is pre-configured,
no local setup required. Codespaces runs on amd64, so all SIEM options including
Splunk Enterprise are available.

## License

Apache 2.0
