# detection-validator

Simulate real CVE-based attacks against a Linux victim, capture genuine kernel-level audit events, and test whether your detection rules actually fire — all on a single MacBook.

```
Vagrant VM (Ubuntu 22.04)          Mac host
┌─────────────────────────┐        ┌──────────────────────────────────────┐
│  auditd                 │        │  Docker                              │
│  victim-agent           │──────▶ │  OpenSearch  (localhost:9200)        │
│  vector (shipper)       │  HEC   │  Splunk mock (localhost:8000/8088)   │
└─────────────────────────┘        └──────────────────────────────────────┘
         ▲                                        │
         │ dv attack                              │ dv validate
         └─ simulate CVE exploit steps            └─ query for rule hits
```

---

## What is `dv`?

There are two separate tools, both called `dv`:

| Tool | File | What it does |
|---|---|---|
| `./dv` | Shell script in project root | Starts/stops Docker containers (`./dv up`, `./dv down`) |
| `dv` | Python CLI installed into `.venv/` | Runs attacks, validates rules, generates reports |

> **In short:** use `./dv up` to start Docker containers. Use `dv doctor`, `dv validate`, `dv attack`, etc. for everything else.

---

## Prerequisites

You need these installed before anything will work.

| Tool | Required version | Install command |
|---|---|---|
| Docker Desktop | ≥ 24 | [docker.com/products/docker-desktop](https://www.docker.com/products/docker-desktop/) |
| Python | 3.12 | `brew install python@3.12` |
| uv (Python package manager) | any | `brew install uv` |
| Vagrant | any | `brew install vagrant` |
| vagrant-qemu plugin | any | `vagrant plugin install vagrant-qemu` |

> **Apple Silicon (M1/M2/M3/M4):** fully supported. The Vagrant VM runs natively via QEMU with Apple Hypervisor Framework — there is no emulation overhead.

---

## Installation

Run these commands once, in order:

```bash
# 1. Clone the repository
git clone <repo-url> detection-validator
cd detection-validator

# 2. Create a Python virtual environment and install the tool
uv venv
uv pip install -e ".[dev]"

# 3. Activate the virtual environment
source .venv/bin/activate

# 4. Confirm the CLI is available
dv --help
```

> **Note:** every time you open a new terminal, run `source .venv/bin/activate` again before using `dv`. Or prefix every command with `.venv/bin/dv` if you prefer not to activate.

---

## Step 1 — Check your environment

Before starting anything, run the pre-flight check:

```bash
dv doctor
```

This checks Python, Docker, Vagrant, the Docker network, running containers, the victim agent, and local intelligence caches. Fix any ✗ errors before continuing. ⚠ warnings are non-blocking.

Expected output once everything is installed and running:

```
dv doctor — environment pre-flight check

  ✓ Python 3.12.5
  ✓ uv 0.11.13
  ✓ Docker 28.3.2
  ✓ Docker daemon running
  ✓ Docker network detectval-lab
  ✓ Vagrant 2.4.9
  ✓ Vagrant plugin vagrant-qemu
  ✓ Vagrant VM running
  ✓ OPENSEARCH_INITIAL_ADMIN_PASSWORD set
  ✓ OpenSearch reachable (HTTP 200)
  ✓ Splunk mock reachable (HTTP 200)
  ✓ Victim agent reachable on port 9098 (Vagrant)
  ✓ ATT&CK KB: 858 techniques
  ✓ KEV cache: 1243 entries

All checks passed.
```

`dv doctor --fix` automatically downloads empty intelligence caches (ATT&CK knowledge base, CVE data).

---

## Step 2 — Start the Docker stack

The Docker stack runs OpenSearch (the SIEM), a Splunk mock receiver, Vector (the log shipper), and a Linux victim container.

```bash
# Set the OpenSearch admin password — pick any strong password you like
export OPENSEARCH_INITIAL_ADMIN_PASSWORD="DetectVal123!"

# Start the full lab stack
./dv up lab --siem opensearch --profile standard
```

> **Important:** save this password in your shell profile so you don't have to type it every session:
> ```bash
> echo 'export OPENSEARCH_INITIAL_ADMIN_PASSWORD="DetectVal123!"' >> ~/.zshrc
> source ~/.zshrc
> ```
> Every `dv validate`, `dv siem status`, and `dv deploy` command reads this environment variable.

Wait about 60 seconds for containers to become healthy, then check:

```bash
docker ps --format "table {{.Names}}\t{{.Status}}"
```

Expected output:

```
NAMES                          STATUS
dv-linux-victim                Up 2 minutes (healthy)
dv-vector                      Up 2 minutes (healthy)
dv-opensearch                  Up 2 minutes (healthy)
dv-opensearch-dashboards       Up 2 minutes (healthy)
detectval-splunk               Up 2 minutes (healthy)
```

Every container should say `(healthy)`. If one says `(starting)`, wait another 30 seconds and check again.

Verify OpenSearch is accepting connections:

```bash
dv siem status
```

Expected:

```
✓ OpenSearch 2.14.0  at https://localhost:9200
  dv-telemetry-*: 0 documents
  .opendistro-alerting-alert*: 0 documents
```

---

## Step 3 — Start the Vagrant VM

The Vagrant VM runs a real Ubuntu 22.04 kernel with `auditd`. This gives you genuine syscall-level telemetry — the kind detection rules actually need to fire against. Docker containers on Mac cannot expose the kernel audit subsystem, which is why a VM is required.

```bash
cd vagrant
vagrant up
```

First run takes about 5 minutes to download the box and provision the VM. Subsequent runs take ~30 seconds. You will see a lot of output — that is normal.

Once it finishes, verify the services inside the VM are running:

```bash
vagrant ssh -c "systemctl status victim-agent vector --no-pager"
```

Both should show `active (running)`.

Verify the agent is reachable from your Mac:

```bash
curl http://localhost:9098/health
```

Expected:

```json
{"status": "ok", "host": "dv-victim", "mode": "vm"}
```

> **Port note:** host port `9098` forwards to VM port `9099`. The Vagrantfile wires this up automatically — you do not need to configure anything.

Now go back to the project root:

```bash
cd ..
```

---

## Step 4 — Run an attack

Two modes are available. Use `--mode exploit` (real HTTP payloads to the vulnerable service) for the most realistic telemetry, or omit it for a lightweight simulation.

### Mode: exploit (recommended — real kernel events)

Sends actual HTTP exploit payloads to the intentionally vulnerable service running on the VM (port 8888). The service triggers real `curl`, `id`, and `/etc/passwd` reads — captured by auditd as genuine kernel syscall events.

```bash
dv attack --cve CVE-2021-44228 --target vagrant --mode exploit
dv attack --cve CVE-2021-26855 --target vagrant --mode exploit
```

Expected output for Log4Shell:

```
⚔  Running attack scenario  cve=CVE-2021-44228  target=vagrant
  Mode: exploit — sending real HTTP payloads to http://localhost:8888

  Log4Shell JNDI injection via X-Api-Version header
  ✓ T1190 + T1059.004  status=exploited
    uid=33(www-data) gid=33(www-data) groups=33(www-data)

✓ 1 exploit(s) delivered.
```

Verify the vulnerable service is reachable before attacking:

```bash
curl http://localhost:8888/health
# Expected: {"status": "vulnerable"}
```

### Mode: simulate (lightweight — synthetic events)

Posts hand-crafted audit records directly to the victim agent. No real exploit is executed. Useful when you just need telemetry quickly without caring about realism.

```bash
dv attack --cve CVE-2021-44228 --target vagrant --agent-port 9098 --watch
dv attack --cve CVE-2021-34527 --target vagrant --agent-port 9098 --watch
dv attack --cve CVE-2021-26855 --target vagrant --agent-port 9098 --watch
```

### Available CVE scenarios

| CVE | Vulnerability | ATT&CK techniques |
|---|---|---|
| `CVE-2021-44228` | Log4Shell RCE | T1190, T1059.004 |
| `CVE-2021-34527` | PrintNightmare | T1068, T1547.012, T1574.001 |
| `CVE-2021-26855` | ProxyLogon SSRF | T1190, T1505.003, T1078, T1552.001 |

---

## Step 5 — Validate your detections

```bash
dv validate examples/detections/sigma/ --since 1
```

This loads every Sigma rule in that directory, builds a query for each one, runs it against OpenSearch, and reports PASS or FAIL:

```
 Rule                            Techniques               Hits  SIEM         Status
 LSASS Memory Dump via TM        T1003.001                   0  opensearch   ✗ FAIL
 Log4Shell JNDI Injection        T1190, T1059.004          156  opensearch   ✓ PASS
 Log4Shell RCE - Outbound Conn   T1190, T1059.004            1  opensearch   ✓ PASS
 MSHTA Spawning Windows Shell    T1218.005, T1059.001       94  opensearch   ✓ PASS
 Nmap Port Scan Detected         T1046                       0  opensearch   ✗ FAIL
 PrintNightmare Spooler Abuse    T1068, T1547.012           14  opensearch   ✓ PASS
 ProxyLogon Exchange SSRF        T1190, T1505.003           62  opensearch   ✓ PASS
 ProxyLogon - Sensitive File     T1190, T1552.001           32  opensearch   ✓ PASS

Results: 8 rule(s)  6 PASS  2 FAIL  0 ERROR  0 SKIP
```

> **Why do LSASS and Nmap fail?** LSASS targets a Windows process — the Vagrant VM runs Linux, so that event is never generated. Nmap requires an active port scan to be run. Both are expected failures.

### How a rule passes

The validator uses a three-layer strategy:
1. **Sigma field-level translation** — translates the `detection:` block to an OpenSearch query and runs it. Most precise.
2. **Technique ID match** — matches the `technique` field against ATT&CK IDs in the rule's tags.
3. **Keyword match** — free-text search across `proctitle`, `cmd_output`, and `message`.

### Time window

`--since 1` means "look at the last 1 hour". If you ran attacks more than an hour ago, increase the window:

```bash
dv validate examples/detections/sigma/ --since 24    # last 24 hours
dv validate examples/detections/sigma/ --since 48    # last 48 hours
```

---

## Step 6 — Generate a report

### CLI summary

```bash
dv validate examples/detections/sigma/ --since 24 --format json | dv report
```

> **How the pipe works:** `dv validate` writes progress messages to stderr (your terminal) and JSON results to stdout. `dv report` reads JSON from stdin. The pipe connects them correctly — you do not need to add any redirects.

Output:

```
╭─────── Validation Summary ────────╮
│ Rules:       7                    │
│ Pass:        4 (57%)              │
│ Fail:        3                    │
│ Error:       0                    │
│ Skip:        0                    │
│                                   │
│ Techniques:  8 covered / 12 total │
│ Generated:   2026-05-26 04:26 UTC │
╰───────────────────────────────────╯

Failing rules
  Rule                 Techniques        SIEM        Status
  LSASS Memory Dump    T1003.001         opensearch  ✗ FAIL
  MSHTA Spawning       T1218.005,T1059   opensearch  ✗ FAIL
  Nmap Port Scan       T1046             opensearch  ✗ FAIL

ATT&CK Tactic Coverage
  Tactic                   Coverage      Techniques covered
  Credential Access        0/1 (0%)      —
  Defense Evasion          1/2 (50%)     T1078
  Execution                1/2 (50%)     T1059.004
  Impact                   1/1 (100%)    T1499
  Initial Access           1/1 (100%)    T1190
  Persistence              2/2 (100%)    T1505.003, T1547.012
  Privilege Escalation     2/2 (100%)    T1068, T1574.001

Passing rules (4): Log4Shell JNDI Injection, PrintNightmare, ProxyLogon, Test
```

### HTML report

```bash
dv validate examples/detections/sigma/ --since 24 --format json | dv report --format html -o report.html
open report.html
```

### SARIF (for GitHub Code Scanning)

```bash
dv validate examples/detections/sigma/ --since 24 --format json | dv report --format sarif -o scan.sarif
```

Upload `scan.sarif` to GitHub Code Scanning and failing rules appear as annotations on pull requests.

### Save results first, report later

```bash
# Save results to a file
dv validate examples/detections/sigma/ --since 24 --format json -o results.json

# Render the saved results later
dv report --results results.json
dv report --results results.json --format html -o report.html
```

---

## Step 7 — Match offline (no SIEM needed)

`dv match` evaluates rules against a local JSONL file instead of querying a live SIEM. Use this in CI or when the Docker stack is not running.

### Export events from the Vagrant VM

```bash
vagrant ssh -c "sudo cat /var/log/audit/audit-events.jsonl" > events.jsonl
```

### Export events from OpenSearch

```bash
curl -sk -u "admin:${OPENSEARCH_INITIAL_ADMIN_PASSWORD}" \
  "https://localhost:9200/dv-telemetry-*/_search?size=1000" \
  -H 'Content-Type: application/json' \
  -d '{"query":{"term":{"source.keyword":"auditd-agent"}}}' \
  | python3 -c "
import json, sys
for h in json.load(sys.stdin)['hits']['hits']:
    print(json.dumps(h['_source']))
" > events.jsonl
```

### Run the match

```bash
dv match --events events.jsonl examples/detections/sigma/ --since 0 --format json | dv report
```

`--since 0` means "use all events in the file regardless of timestamp". Notice the evaluation time — it is usually under 0.05 seconds because everything runs in memory with no network calls.

---

## Offline analysis pipeline

This sequence parses, maps, and enriches your rules entirely on disk — no SIEM or network required.

```bash
# 1. Parse all rule files into a unified JSON format
dv ingest examples/detections/sigma/ -o canonical.jsonl

# 2. Validate and map rules to ATT&CK techniques
dv map -i canonical.jsonl -o mapped.jsonl

# 3. Fill in technique names, CVE metadata, and severity scores
dv enrich -i mapped.jsonl -o enriched.jsonl
```

After enrichment you can:

```bash
# Generate an ATT&CK Navigator layer (shows which techniques you cover)
dv navigator -d enriched.jsonl -o layer.json
# Open https://mitre-attack.github.io/attack-navigator/
# Click "Open Existing Layer" → "Upload from local" → select layer.json

# Generate a coverage badge
dv badge -d enriched.jsonl --format json    # JSON metrics
dv badge -d enriched.jsonl -o coverage.svg  # SVG badge
```

---

## CVE coverage analysis

This workflow answers: *"Do I have detections for the techniques an attacker would use to exploit this CVE?"*

```bash
# 1. Update local intelligence caches (run once; re-run monthly)
dv intel update --source attack
dv intel update --source cve

# 2. Build the enriched corpus (same pipeline as above)
dv ingest examples/detections/ -o canonical.jsonl
dv map -i canonical.jsonl -o mapped.jsonl
dv enrich -i mapped.jsonl -o enriched.jsonl

# 3. Analyze coverage for one or more CVEs
dv cve-coverage --cve CVE-2021-44228 -d enriched.jsonl
dv cve-coverage --cve CVE-2021-44228,CVE-2021-34527,CVE-2021-26855 -d enriched.jsonl
```

Sample output:

```
CVE-2021-44228  KEV  CVSS=10.0  EPSS=0.945  coverage=100%  residual_risk=0.000
  ✓ T1059  execution      conf=0.85   ← Log4Shell JNDI Injection Attempt
  ✓ T1190  initial-access conf=0.80   ← Log4Shell JNDI Injection Attempt
  ✓ T1499  impact         conf=0.60   ← Test
```

**Reading the output:**

| Field | Meaning |
|---|---|
| **KEV** | This CVE is in CISA's Known Exploited Vulnerabilities catalog — actively exploited in the wild |
| **CVSS** | Severity score from NVD (0–10, higher = worse) |
| **EPSS** | Probability of exploitation in the next 30 days (source: FIRST.org) |
| **coverage** | Percentage of mapped techniques covered by at least one detection |
| **residual_risk** | `CVSS × EPSS × (1 − coverage)` — how much uncovered risk remains; lower is better |
| **conf** | Mapping confidence: 1.0 = explicit rule tag; ~0.85 = CTID dataset; varies for CWE inference |

### Closing a coverage gap

If `cve-coverage` shows ✗ for a technique, add that technique to a rule:

```yaml
# In your Sigma rule's tags section:
tags:
    - attack.T1499          # the technique you want to cover
    - cve.2021.44228        # links this rule to the CVE in coverage reports
```

Then re-run `ingest → map → enrich → cve-coverage` to confirm the gap is closed.

---

## Format conversion (migrate)

Convert detection rules between formats without touching a SIEM:

```bash
# Sigma → Splunk savedsearches.conf
dv migrate sigma splunk --rules examples/detections/sigma/ -o searches.conf

# Sigma → KQL (Azure Sentinel / Microsoft Defender)
dv migrate sigma kql --rules examples/detections/sigma/ -o queries.kql

# Normalize and re-export as clean Sigma YAML
dv migrate sigma sigma --rules examples/detections/sigma/ -o normalised/
```

---

## Deploy rules to a live SIEM

Push rules directly to a running SIEM so they fire automatically on new events.

```bash
# Always preview first — this makes no changes
dv deploy examples/detections/sigma/ --siem opensearch --dry-run

# Deploy for real — creates one OpenSearch Alerting monitor per rule
dv deploy examples/detections/sigma/ --siem opensearch

# Deploy to Splunk — creates saved searches with an hourly schedule
dv deploy examples/detections/sigma/ --siem splunk
```

---

## Live rule development with watch

`dv watch` polls your rules directory and re-runs validation every time you save a file:

```bash
# Fast offline feedback — re-matches against a local event file on every save
dv watch examples/detections/sigma/ --events events.jsonl

# Live feedback — re-queries OpenSearch on every save
dv watch examples/detections/sigma/ --siem opensearch --since 1

# Increase polling frequency during active development
dv watch examples/detections/sigma/ --events events.jsonl --interval 2
```

Press `Ctrl+C` to stop.

---

## Inspect the running stack

```bash
# Check OpenSearch version, connectivity, and document counts
dv siem status

# Run a test query and show the most recent events
dv siem test --size 5

# Check victim agent health
dv agent status

# Check SIEM and agent in one line
dv siem status && dv agent status
```

---

## View telemetry in OpenSearch Dashboards

Open `https://localhost:5601` in your browser. Log in with username `admin` and the password you set in `OPENSEARCH_INITIAL_ADMIN_PASSWORD`.

Go to **Discover** and select the `dv-telemetry-*` index pattern. Set the time range (top right) to cover your last attack run.

Useful KQL queries:

| Query | What it shows |
|---|---|
| `host: dv-victim` | All events from the Vagrant VM |
| `technique.keyword: T1190` | Exploitation events |
| `technique.keyword: T1059.004` | Shell execution events |
| `technique.keyword: T1068` | Privilege escalation events |
| `proctitle: jndi` | Free-text search for Log4Shell payloads |

### Direct API access

```bash
# List the 5 most recent events
curl -sk -u "admin:${OPENSEARCH_INITIAL_ADMIN_PASSWORD}" \
  "https://localhost:9200/dv-telemetry-*/_search?size=5&sort=timestamp:desc&pretty"

# Search for a specific technique
curl -sk -u "admin:${OPENSEARCH_INITIAL_ADMIN_PASSWORD}" \
  "https://localhost:9200/dv-telemetry-*/_search?pretty" \
  -H 'Content-Type: application/json' \
  -d '{"query": {"term": {"technique.keyword": "T1190"}}}'
```

---

## Telemetry field reference

Events written by the victim agent contain these fields:

| Field | Example | What it means |
|---|---|---|
| `technique` | `T1190` | ATT&CK technique ID that was simulated |
| `key` | `network_connect` | The audit rule that fired |
| `exe` | `/usr/bin/curl` | Full path of the process that ran |
| `uid` | `33` | Numeric UID of the process (33 = www-data) |
| `cmd_output` | `uid=0(root)...` | Captured output of the command |
| `host` | `dv-victim` | Hostname of the source machine |
| `cve` | `CVE-2021-44228` | CVE scenario that generated this event |
| `timestamp` | `2026-05-26T04:26:00Z` | ISO 8601 UTC |

---

## Writing detection rules

Rules live in `examples/detections/sigma/`. Each is a YAML file.

Minimum working rule:

```yaml
title: My Detection Rule
id: a1b2c3d4-e5f6-7890-abcd-ef1234567890
status: experimental
description: Detects something suspicious
logsource:
    category: process_creation
detection:
    keywords:
        - suspicious_process
    condition: keywords
tags:
    - attack.T1059.004
level: high
```

Key fields:

| Field | What it does |
|---|---|
| `id` | Unique UUID. Generate one: `python3 -c "import uuid; print(uuid.uuid4())"` |
| `tags` | Links the rule to ATT&CK techniques (`attack.T1234`) and CVEs (`cve.2021.44228`) |
| `detection.keywords` | Simple string matching against event fields |
| `level` | Severity: `informational` / `low` / `medium` / `high` / `critical` |

After writing a rule, test it immediately:

```bash
# Offline — instant, no SIEM needed
dv match --events events.jsonl examples/detections/sigma/ --since 0

# Or live against OpenSearch
dv validate examples/detections/sigma/ --since 24
```

---

## Vagrant VM reference

```bash
cd vagrant

vagrant up          # create and provision VM (~5 min on first run)
vagrant ssh         # open a shell inside the VM
vagrant halt        # stop the VM (preserves disk)
vagrant destroy -f  # delete the VM entirely

# Re-run provisioning after editing files/ or provision.sh
vagrant provision

# Check all three services inside the VM
vagrant ssh -c "systemctl status victim-agent vector auditd --no-pager"

# Watch audit events arriving in real time
vagrant ssh -c "tail -f /var/log/audit/audit-events.jsonl"
```

---

## Docker stack reference

```bash
# Start the lab with OpenSearch (recommended)
./dv up lab --siem opensearch --profile standard

# Start with Splunk Enterprise (amd64 only — not available on Apple Silicon)
./dv up lab --siem splunk --profile standard

# Start both SIEMs at once
./dv up lab --siem opensearch,splunk

# Stop everything
./dv down lab --siem opensearch

# Check status
./dv status

# Tail logs from a container
./dv logs dv-opensearch -f
./dv logs dv-vector -f
./dv logs dv-linux-victim -f
```

### Resource profiles

| Profile | RAM per service | Recommended for |
|---|---|---|
| `standard` | ~1 GB | Default — recommended for most Macs |
| `tiny` | ~600 MB | Use only if containers keep restarting due to low memory |
| `full` | 2 GB+ | CI servers or dedicated machines |

---

## GitHub Actions

Add detection validation to your CI pipeline:

```yaml
name: Validate detections
on: [push, pull_request]

jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install detection-validator
        run: pip install uv && uv pip install --system .

      - name: Match offline
        run: |
          dv match --events tests/fixtures/events.jsonl \
            detections/ --since 0 --format json | \
          dv report --format sarif -o scan.sarif

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: scan.sarif
```

---

## Troubleshooting

### `dv: command not found`

The virtual environment is not active. Run:

```bash
source .venv/bin/activate
```

Or use the full path: `.venv/bin/dv`

### `dv doctor` shows "OpenSearch auth failed"

Make sure the password environment variable matches what OpenSearch was started with:

```bash
export OPENSEARCH_INITIAL_ADMIN_PASSWORD="DetectVal123!"
dv siem status    # confirms the password works
```

### OpenSearch container fails to start — `vm.max_map_count too low`

```bash
docker run --rm --privileged alpine sysctl -w vm.max_map_count=262144
./dv up lab --siem opensearch --profile standard
```

### Containers restart or run out of memory

In Docker Desktop → Settings → Resources → Memory: set to at least **8 GB**.

If still unstable, fall back to the `tiny` profile:

```bash
./dv up lab --siem opensearch --profile standard
```

### Vagrant VM fails to start — QEMU / HVF error

Make sure Docker Desktop and Terminal have full disk access in System Settings → Privacy & Security.

```bash
vagrant plugin update vagrant-qemu
cd vagrant && vagrant destroy -f && vagrant up
```

### `dv validate` shows 0 hits for all rules

The default `--since 1` window looks back only 1 hour. If your attacks ran earlier, extend the window:

```bash
dv validate examples/detections/sigma/ --since 24
```

Also confirm events landed in OpenSearch:

```bash
dv siem status          # check document count
dv siem test --size 5   # show sample events
```

### `dv match` returns 0 hits

Check that your events file is not empty and is valid JSON:

```bash
wc -l events.jsonl                              # should be > 0
head -1 events.jsonl | python3 -m json.tool    # should print valid JSON
```

---

## Example detections

Ready-to-use rules in `examples/detections/`:

| Format | File | CVE | Techniques |
|---|---|---|---|
| Sigma | `sigma/log4shell_jndi_injection.yml` | CVE-2021-44228 | T1190, T1059.004 |
| Sigma | `sigma/log4shell_process_exec.yml` | CVE-2021-44228 | T1190, T1059.004 |
| Sigma | `sigma/printnightmare_spooler_abuse.yml` | CVE-2021-34527 | T1068, T1547.012, T1574.001 |
| Sigma | `sigma/proxylogon_exchange_ssrf.yml` | CVE-2021-26855 | T1190, T1505.003, T1078 |
| Sigma | `sigma/proxylogon_process_exec.yml` | CVE-2021-26855 | T1190, T1552.001, T1078 |
| Sigma | `sigma/credential_dump_lsass.yml` | — | T1003.001 |
| Sigma | `sigma/network_scan_nmap.yml` | — | T1046 |
| Splunk | `splunk/savedsearches.conf` | — | T1059.001, T1570 |
| KQL | `kql/sentinel_aad_password_spray.yml` | — | T1110.003 |

> `log4shell_process_exec.yml` and `proxylogon_process_exec.yml` are **field-based** rules that match real kernel-level auditd observables (`key`, `exe`, `uid`) rather than technique IDs. They fire only when the real exploit mode is used.

---

## Command reference

| Command | What it does |
|---|---|
| `dv doctor` | Pre-flight check: Python, Docker, Vagrant, SIEMs, agent, caches |
| `dv doctor --fix` | Same, plus auto-download empty intelligence caches |
| `dv attack` | Execute CVE exploit steps against the victim VM |
| `dv validate` | Query live SIEM for rule hits, report PASS/FAIL |
| `dv match` | Same evaluation offline against a local JSONL event file |
| `dv report` | Render results as CLI summary / SARIF / HTML |
| `dv watch` | Re-validate automatically whenever rule files change |
| `dv ingest` | Parse Sigma/Splunk/KQL/YARA/EQL rules to canonical JSONL |
| `dv map` | Map parsed rules to ATT&CK techniques |
| `dv enrich` | Fill technique names, CVE metadata, and severity |
| `dv migrate` | Convert rules between formats (sigma → splunk / kql / sigma) |
| `dv deploy` | Push rules to a live SIEM as alerting monitors or saved searches |
| `dv badge` | Generate an SVG or JSON ATT&CK coverage badge |
| `dv siem status` | Check SIEM connectivity and document counts |
| `dv siem test` | Run a test query and display sample events |
| `dv agent status` | Check victim agent health endpoint |
| `dv agent logs` | Fetch recent events from the victim agent |
| `dv cve-coverage` | Analyze detection coverage gaps per CVE |
| `dv navigator` | Export ATT&CK Navigator layer from detection corpus |
| `dv intel update` | Refresh local ATT&CK, CVE, EPSS, KEV caches |

---

## Architecture

```
┌─ Python CLI (dv) ──────────────────────────────────────────────┐
│  dv doctor       — pre-flight check: tools, containers, caches │
│  dv attack       — simulate CVE exploit steps on victim        │
│  dv validate     — query live SIEM, report PASS/FAIL per rule  │
│  dv match        — same evaluation offline against a JSONL file│
│  dv report       — render results as CLI / SARIF / HTML        │
│  dv watch        — re-validate on rule file changes            │
│  dv ingest       — parse Sigma/Splunk/KQL/YARA/EQL to JSONL    │
│  dv map          — map rules to ATT&CK techniques              │
│  dv enrich       — fill technique names, CVE metadata, severity│
│  dv migrate      — convert rules between formats               │
│  dv deploy       — push rules to OpenSearch / Splunk           │
│  dv badge        — generate SVG / JSON coverage badge          │
│  dv siem         — check connectivity, run test queries        │
│  dv agent        — check agent health, fetch recent events     │
│  dv cve-coverage — analyze coverage gaps per CVE               │
│  dv navigator    — export ATT&CK Navigator layer               │
└────────────────────────────────────────────────────────────────┘

┌─ Shell script (./dv) ──────────────────────────────────────────┐
│  ./dv up lab --siem opensearch   — start Docker containers     │
│  ./dv down lab                   — stop Docker containers      │
│  ./dv status                     — show running services       │
│  ./dv logs <service>             — tail container logs         │
└────────────────────────────────────────────────────────────────┘

┌─ Telemetry pipeline ───────────────────────────────────────────┐
│  Vagrant VM (Ubuntu 22.04 ARM64)                               │
│    auditd → /var/log/audit/audit-events.jsonl                  │
│    victim-agent (port 9099) ← dv attack                        │
│    vector → OpenSearch (9200) + Splunk HEC (8088)              │
│                                                                 │
│  Docker linux-victim container (synthetic events)              │
│    stdout → vector → OpenSearch + Splunk HEC                   │
└────────────────────────────────────────────────────────────────┘

┌─ SIEMs ────────────────────────────────────────────────────────┐
│  OpenSearch  localhost:9200   Dashboards: localhost:5601       │
│  Splunk mock localhost:8088   UI:         localhost:8000       │
└────────────────────────────────────────────────────────────────┘
```

---

## Apple Silicon notes

All core services run natively on ARM64.

| Component | ARM64 status |
|---|---|
| OpenSearch + Dashboards | ✅ native |
| Splunk mock (HEC) | ✅ native (Python-based) |
| Vagrant VM via QEMU/HVF | ✅ native ARM64 kernel |
| Docker Linux victim | ✅ native |
| Splunk Enterprise | ❌ amd64 only — use `--siem opensearch` instead |

---

## License

Apache 2.0
