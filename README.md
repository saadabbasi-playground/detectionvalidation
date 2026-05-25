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
dv-linux-victim                   Up X minutes (healthy)   ← optional, see below
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
detection-validator ingest detections/ -o canonical.jsonl

# 3. Map to ATT&CK
detection-validator map -i canonical.jsonl -o mapped.jsonl --mode hybrid

# 4. Generate a SARIF report for GitHub Code Scanning
./dv report --format sarif --output results.sarif
```

---

## CVE-based detection workflow

This workflow starts from a CVE, finds the techniques an attacker would use to
exploit it, checks your detection corpus for coverage, and surfaces gaps.

### Sample detections

Three ready-to-use Sigma rules are included under `examples/detections/sigma/`:

| File | CVE | ATT&CK techniques |
|---|---|---|
| `log4shell_jndi_injection.yml` | CVE-2021-44228 | T1190, T1059.004 |
| `printnightmare_spooler_abuse.yml` | CVE-2021-34527 | T1068, T1547.012, T1574.001 |
| `proxylogon_exchange_ssrf.yml` | CVE-2021-26855 | T1190, T1505.003, T1078 |

Each rule uses the `cve.YYYY.NNNNN` tag convention so the CVE mapper can link
them to the coverage analysis automatically.

### Running the pipeline

```bash
# Step 1 — pull CVE metadata (NVD, CISA KEV, EPSS) and CTID technique mappings
detection-validator intel update --source cve
detection-validator intel update --source attack

# Step 2 — ingest and normalize all detections
detection-validator ingest examples/detections/ -o canonical.jsonl

# Step 3 — map to ATT&CK (explicit tags + CWE inference)
detection-validator map -i canonical.jsonl -o mapped.jsonl --mode hybrid

# Step 4 — analyze coverage for the three CVEs
detection-validator cve-coverage \
  --cve CVE-2021-44228,CVE-2021-34527,CVE-2021-26855 \
  --detections mapped.jsonl
```

### Sample output

```
CVE-2021-26855  KEV CVSS=9.1  EPSS=0.943  coverage=0%  residual_risk=8.585
  ✗ T1090  command-and-control  conf=0.75

CVE-2021-34527  KEV CVSS=8.8  EPSS=0.942  coverage=0%  residual_risk=8.293
  (no techniques mapped — CWE missing from NVD; add cve.2021.34527 tag to
   your Splunk/KQL rules covering T1068 to register coverage)

CVE-2021-44228  KEV CVSS=10.0  EPSS=0.945  coverage=67%  residual_risk=3.149
  ✓ T1059  execution  conf=0.85  ← Log4Shell JNDI Injection Attempt, ...
  ✓ T1190  initial-access  conf=0.80  ← Log4Shell JNDI Injection Attempt, ...
  ✗ T1499  impact  conf=0.60
```

**Reading the output:**
- **KEV** — CVE is on CISA's Known Exploited Vulnerabilities catalog (actively exploited)
- **EPSS** — probability of exploitation in the next 30 days (source: FIRST.org)
- **residual_risk** — `CVSS × EPSS × (1 − coverage_ratio)`; range 0–10
- **✓ / ✗** — whether your detection corpus covers that technique
- **conf** — mapping confidence (CTID > CWE inference; 1.0 = explicit tag in the rule)

### Adding a detection to close a gap

If `cve-coverage` reports ✗ for a technique, create a Sigma rule and tag it:

```yaml
tags:
    - attack.T1499          # the uncovered technique
    - cve.2021.44228        # links this rule to the CVE in coverage reports
```

Re-run `ingest → map → cve-coverage` to confirm the gap closes.

### Notes on technique mapping sources

Technique inference works in priority order:

1. **Explicit tags** in the rule (`attack.TXXXX`) — confidence 1.0
2. **CTID dataset** ([center-for-threat-informed-defense/attack_to_cve](https://github.com/center-for-threat-informed-defense/attack_to_cve)) — ~827 CVE mappings, confidence 0.90
3. **CWE inference** — maps NVD CWEs to ATT&CK via a built-in table, confidence varies

If a CVE has no CWE in NVD and no CTID entry, no techniques are inferred
(as seen for CVE-2021-34527 above). Adding explicit `attack.TXXXX` tags to
your rules is the most reliable way to ensure coverage is counted.

---

## Linux victim container

`dv-linux-victim` is a Ubuntu 22.04 container that generates realistic security
telemetry. It runs `auditd` and streams events as JSON to stdout, which Vector
picks up via the Docker socket and forwards to OpenSearch and Splunk.

### What it captures

| Audit key | ATT&CK technique | Example |
|---|---|---|
| `exec` | T1059 Command & Scripting | Any `execve` syscall |
| `shell_exec` | T1059.004 Unix Shell | `/bin/bash`, `/bin/sh` launches |
| `network_connect` | T1190 Exploit Public-Facing App | `connect()` syscalls |
| `priv_change` | T1068 Privilege Escalation | `setuid()`, `setgid()` |
| `sensitive_file` | T1552 Credentials in Files | Reads to `/etc/shadow`, `/etc/sudoers` |
| `sudo_exec` | T1548 Abuse Elevation Control | `/usr/bin/sudo` execution |
| `cron_modify` | T1547.003 Cron | Writes to `/etc/cron.d` |
| `module_load` | T1547.006 Kernel Modules | `init_module` syscall |

### Starting the container

```bash
# Build the image (once)
docker build --platform linux/arm64 -t detection-validator/linux-victim:dev docker/linux-victim/

# Start on the detectval-lab network (Vector picks up stdout automatically)
docker run -d --name dv-linux-victim \
  --network detectval-lab \
  --cap-add AUDIT_WRITE --cap-add AUDIT_CONTROL --cap-add SYS_PTRACE \
  --security-opt seccomp:unconfined \
  -e HOSTNAME=linux-victim \
  detection-validator/linux-victim:dev
```

> **Mac M1:** The Linux kernel inside Docker Desktop's LinuxKit VM does not expose
> the audit subsystem to containers by default. The victim falls back to
> **synthetic-event mode**, which emits the same JSON schema at 10-second intervals —
> enough to validate the full pipeline (Vector → OpenSearch/Splunk) without real kernel
> hooks. Real auditd events require a native Linux host.

### Verifying events reach the SIEMs

```bash
# OpenSearch: count events from the victim
curl -sk -u admin:$OPENSEARCH_INITIAL_ADMIN_PASSWORD \
  "https://localhost:9200/dv-telemetry-*/_count" \
  -H 'Content-Type: application/json' \
  -d '{"query":{"term":{"container.keyword":"dv-linux-victim"}}}'

# Splunk: search via mock REST API
curl -s http://localhost:8000/services/search/jobs \
  -X POST -H "Authorization: Splunk detectval-hec-token" \
  -d "search=dv-linux-victim" \
  -H "Content-Type: application/x-www-form-urlencoded"
```

---

## Architecture

```
┌─ core ──────────────────────────────────────────────────────────┐
│  detection_validator  (FastAPI + Celery)                         │
│  parsers ▸ normalizer ▸ validator ▸ coverage ▸ reporters        │
└──────────────────────────────────────────────────────────────────┘
        │                    │                    │
┌─ lab ─┴──────┐    ┌────────┴──────┐    ┌───────┴──────────────┐
│  attacker    │    │  linux-victim │    │  atomic-runner        │
│  (Kali-slim) │    │  (auditd →    │    │  (invoke-atomicredteam│
│  nuclei,ART  │    │   JSON stdout │    │   + ART library)     │
└──────────────┘    └───────────────┘    └──────────────────────┘
        │                    │ docker_logs
┌─ siem ─┴──────────────────┴──────────────────────────────────┐
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
