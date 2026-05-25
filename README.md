# detection-validator

Multi-SIEM detection validation platform. Simulate CVE-based attacks, capture real auditd telemetry, and validate detection rules against live SIEM data — all on a MacBook M1.

```
dv doctor  # check your environment before the first run
dv attack  --cve CVE-2021-44228 --target vagrant --watch
dv validate examples/detections/sigma/ --since 1 --format json | dv report
dv match   --events events.jsonl examples/detections/sigma/ --since 0 --format json | dv report --format html -o report.html
dv cve-coverage --cve CVE-2021-44228 --detections mapped.jsonl
```

---

## How it works

```
Vagrant VM (Ubuntu 22.04)          Mac host
┌─────────────────────────┐        ┌──────────────────────────────────────┐
│  auditd                 │        │  Docker                              │
│  victim-agent.py        │──────▶ │  OpenSearch  (localhost:9200)        │
│  vector (shipper)       │  HEC   │  Splunk mock (localhost:8000/8088)   │
└─────────────────────────┘        └──────────────────────────────────────┘
         ▲                                        │
         │ dv attack                              │ dv validate
         └─ simulate CVE steps                   └─ query for technique hits
```

1. **`dv attack`** sends simulated exploit steps to the Vagrant VM. The victim agent executes them and writes audit events to `/var/log/audit/audit-events.jsonl`.
2. **Vector** ships those events to OpenSearch and Splunk on the Mac host.
3. **`dv validate`** loads your Sigma/Splunk/KQL detection rules, queries each SIEM for matching events, and reports PASS/FAIL per rule.
4. **`dv match`** does the same evaluation entirely offline — no SIEM needed. Point it at a raw JSONL event file and it returns identical results in milliseconds.
5. **`dv report`** takes results from either command and renders them as a CLI summary, SARIF file, or self-contained HTML page.

---

## Prerequisites

| Requirement | Version | Install |
|---|---|---|
| Docker Desktop | ≥ 4.27 | [docker.com](https://www.docker.com/products/docker-desktop/) |
| Python | 3.12 | `brew install python@3.12` |
| uv | latest | `brew install uv` |
| Vagrant | latest | `brew install vagrant` |
| vagrant-qemu plugin | latest | `vagrant plugin install vagrant-qemu` |

> **Apple Silicon (M1/M2/M3/M4):** fully supported. The Vagrant VM runs natively via QEMU + Apple Hypervisor Framework (no emulation).

---

## Step 0 — Check your environment

Run this once after cloning to verify all prerequisites are in place:

```bash
git clone <repo-url> detection-validator
cd detection-validator

uv venv && uv pip install -e ".[dev]" && source .venv/bin/activate

dv doctor
```

`dv doctor` checks Python, Docker, Vagrant, running containers, the victim agent, and local intelligence caches. Fix any errors it reports before continuing.

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

`dv doctor --fix` will automatically download empty intelligence caches.

---

## Step 1 — Start the SIEM stack

```bash
# Set the OpenSearch admin password (required before starting)
export OPENSEARCH_INITIAL_ADMIN_PASSWORD="<your-password>"

# Start OpenSearch + Splunk + Vector shipper
./dv up lab --siem opensearch --profile tiny
```

Confirm everything is healthy after ~60 seconds:

```bash
docker ps --format "table {{.Names}}\t{{.Status}}"
```

Expected output:
```
NAMES                          STATUS
dv-opensearch                  Up X minutes (healthy)
dv-opensearch-dashboards       Up X minutes (healthy)
dv-redis                       Up X minutes (healthy)
dv-vector                      Up X minutes (healthy)
detectval-splunk               Up X minutes (healthy)
```

> **Tip:** Use `--profile tiny` on a 16 GB MacBook to keep memory usage under control (≤1 GB per service).

---

## Step 2 — Start the Vagrant VM

The Vagrant VM runs a real Ubuntu 22.04 kernel with `auditd`, giving you genuine syscall-level telemetry. This is required for realistic detection validation on Mac (Docker on Mac cannot expose the audit subsystem to containers).

```bash
cd vagrant
vagrant up      # first run: ~5 minutes to provision
```

This provisions:
- `auditd` with rules that tag syscalls with ATT&CK technique IDs
- `victim-agent.py` — HTTP server on port 9099 that executes simulated attack steps and records audit events
- `vector` — ships audit events from `/var/log/audit/audit-events.jsonl` to OpenSearch and Splunk on the Mac host

Verify services are running:

```bash
vagrant ssh -c "systemctl status victim-agent vector --no-pager"
```

Verify the agent is reachable from the Mac host:

```bash
curl http://localhost:9098/health
# Expected: {"status": "ok", "host": "dv-victim", "mode": "vm"}
```

> **Port mapping:** host `9098` → VM `9099`. The Vagrantfile uses QEMU's `extra_netdev_args` to forward this port on the same SLiRP network interface as SSH.

---

## Step 3 — Simulate an attack

```bash
# From the project root (not the vagrant/ directory)
dv attack --cve CVE-2021-44228 --target vagrant --agent-port 9098 --watch
```

The `--watch` flag waits 5 seconds for Vector to flush, then shows the events that landed in OpenSearch:

```
⚔  Running attack scenario  cve=CVE-2021-44228  target=vagrant
   Victim: dv-linux-victim  agent: http://localhost:9098/health

Scenario: Log4Shell Remote Code Execution
  CVE: CVE-2021-44228  CVSS: 10.0

  ✓ T1190     key=network_connect  rc=0
  ✓ T1059.004 key=shell_exec       rc=0
    uid=0(root) gid=0(root) groups=0(root) root Linux dv-victim 5.15.0-143-generic

✓ 2 steps executed.

Attack events in OpenSearch (last 20):
  T1190         network_connect   exe=/usr/bin/curl   uid=33
  T1059.004     shell_exec        exe=/bin/bash       uid=33
    uid=0(root) gid=0(root) ...
```

### Available CVE scenarios

| CVE | Scenario | Techniques simulated |
|---|---|---|
| CVE-2021-44228 | Log4Shell RCE | T1190, T1059.004 |
| CVE-2021-34527 | PrintNightmare | T1068, T1547.012, T1574.001 |
| CVE-2021-26855 | ProxyLogon SSRF | T1190, T1505.003, T1078 |

```bash
dv attack --cve CVE-2021-34527 --target vagrant --agent-port 9098 --watch
dv attack --cve CVE-2021-26855 --target vagrant --agent-port 9098 --watch
```

---

## Step 4 — Validate detections

```bash
dv validate examples/detections/sigma/ --since 1
```

This loads every Sigma rule under `examples/detections/sigma/`, translates each to a live OpenSearch query, and reports whether the rule fired against telemetry from the last hour:

```
 Rule                       Techniques              Hits  SIEM         Status
 LSASS Memory Dump          T1003.001                  0  opensearch   ✗ FAIL
 Log4Shell JNDI Injection   T1190, T1059.004           6  opensearch   ✓ PASS
 MSHTA Spawning Shell       T1218.005, T1059.001       0  opensearch   ✗ FAIL
 Nmap Port Scan Detected    T1046                      0  opensearch   ✗ FAIL
 PrintNightmare Spooler     T1068, T1547.012           4  opensearch   ✓ PASS
 ProxyLogon Exchange SSRF   T1190, T1505.003           5  opensearch   ✓ PASS
 Test                       T1499, T1059.004           3  opensearch   ✓ PASS

Results: 7 rule(s)  4 PASS  3 FAIL  0 ERROR  0 SKIP  (1.3s)
Covered techniques: T1059.004, T1068, T1078, T1190, T1499, T1505.003, T1547.012, T1574.001
```

**Why do LSASS, MSHTA, and Nmap fail?** Those are Windows-specific or require an active port scan. The Linux VM only generates Linux syscall events, so rules targeting Windows processes will always show no hits.

### How validation works

A rule **PASSES** if the SIEM returns at least one hit matching either:
- The ATT&CK technique IDs declared in the rule's tags (e.g. `attack.T1190`), matched against the `technique` field in the index, **or**
- Keywords extracted from the rule's `detection` section, matched against `proctitle`, `cmd_output`, and `message` fields.

### Validate against both SIEMs

```bash
dv validate examples/detections/sigma/ --siem opensearch,splunk --since 24
```

### Other options

```bash
# Extend the time window (useful if attacks were run earlier)
dv validate examples/detections/sigma/ --since 48

# Output JSON for scripting
dv validate examples/detections/sigma/ --format json | python3 -m json.tool

# Write updated JSONL with validation_status field
dv validate examples/detections/sigma/ -o validated.jsonl
```

---

## Step 4b — Match offline (no SIEM needed)

`dv match` evaluates the same rules against a local JSONL file instead of querying a live SIEM. Use it in CI, for replaying captured events, or when the Docker stack isn't running.

### Export events from the Vagrant VM

```bash
vagrant ssh -c "sudo cat /var/log/audit/audit-events.jsonl" > events.jsonl
```

### Export events from OpenSearch

```bash
curl -sk -u admin:"$OPENSEARCH_INITIAL_ADMIN_PASSWORD" \
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
dv match --events events.jsonl examples/detections/sigma/ --since 2
```

Output is identical to `dv validate`:

```
 Rule                       Techniques              Hits  Source  Status
 LSASS Memory Dump          T1003.001                  0  local   ✗ FAIL
 Log4Shell JNDI Injection   T1190, T1059.004           8  local   ✓ PASS
   T1190
 PrintNightmare Spooler     T1068, T1547.012           4  local   ✓ PASS
   setuid(0) attempt, current uid: 0
 ProxyLogon Exchange SSRF   T1190, T1505.003           6  local   ✓ PASS
 Test                       T1499, T1059.004           5  local   ✓ PASS
   /bin/bash -c curl -sk http://127.0.0.1:8080/ ...

Results: 7 rule(s)  4 PASS  3 FAIL  0 ERROR  0 SKIP  (0.0s)
```

Note the `(0.0s)` — 18,000 events evaluated in milliseconds with no network round-trips.

### Pipe into dv report

```bash
dv match --events events.jsonl examples/detections/sigma/ --since 0 --format json | dv report
dv match --events events.jsonl examples/detections/sigma/ --since 0 --format json | dv report --format html -o report.html
```

### validate vs match

| | `dv validate` | `dv match` |
|---|---|---|
| Event source | Live SIEM query | Local JSONL file |
| Requires SIEMs running | Yes | No |
| Tests full ingestion pipeline | Yes | No |
| Speed | ~1–2 s (network) | < 0.1 s (in-memory) |
| Works in offline CI | No | Yes |

---

## Step 5 — Generate a report

`dv report` reads the JSON output from `dv validate` and renders it in the format you need.

### Pipe directly from validate

```bash
# CLI summary (default)
dv validate examples/detections/sigma/ --since 1 --format json | dv report

# Self-contained HTML page
dv validate examples/detections/sigma/ --since 1 --format json | dv report --format html -o report.html

# SARIF 2.1.0 for GitHub Code Scanning
dv validate examples/detections/sigma/ --since 1 --format json | dv report --format sarif -o scan.sarif
```

### Save results first, then report

```bash
dv validate examples/detections/sigma/ --since 1 --format json -o results.json
dv report --results results.json --format html -o report.html
```

### CLI report output

```
╭─────── Validation Summary ────────╮
│ Rules:       7                    │
│ Pass:        4 (57%)              │
│ Fail:        3                    │
│ Error:       0                    │
│ Skip:        0                    │
│                                   │
│ Techniques:  8 covered / 12 total │
│ Generated:   2026-05-25 09:45 UTC │
╰───────────────────────────────────╯

Failing rules
  Rule                    Techniques         SIEM        Status
  LSASS Memory Dump       T1003.001          opensearch  ✗ FAIL
  MSHTA Spawning Shell    T1218.005,T1059    opensearch  ✗ FAIL
  Nmap Port Scan          T1046              opensearch  ✗ FAIL

ATT&CK Tactic Coverage
  Tactic                   Coverage       Techniques covered
  Credential Access        0/1 (0%)       —
  Defense Evasion          1/2 (50%)      T1078
  Execution                1/2 (50%)      T1059.004
  Impact                   1/1 (100%)     T1499
  Initial Access           1/1 (100%)     T1190
  Persistence              2/2 (100%)     T1505.003, T1547.012
  Privilege Escalation     2/2 (100%)     T1068, T1574.001

Passing rules (4): Log4Shell JNDI Injection, PrintNightmare, ProxyLogon, Test
```

### Report formats

| Format | Use case |
|---|---|
| `cli` | Interactive terminal summary with tactic coverage breakdown |
| `json` | Pretty-printed results for scripting or downstream tools |
| `sarif` | GitHub Code Scanning — failing rules appear as PR annotations |
| `html` | Self-contained dark-theme page with summary cards and coverage bars |

### SARIF in GitHub Actions

Upload the SARIF file to GitHub Code Scanning so failing rules appear as annotations on pull requests:

```yaml
- name: Validate detections
  run: |
    dv validate detections/ --since 24 --format json | \
    dv report --format sarif -o scan.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: scan.sarif
```

---

## Step 6 — View telemetry

### OpenSearch Dashboards

```
https://localhost:5601
```
Login with the admin credentials you set in `OPENSEARCH_INITIAL_ADMIN_PASSWORD`. Go to **Discover** and select the `dv-telemetry-*` index pattern.

Useful KQL queries:

| Query | What it shows |
|---|---|
| `host: dv-victim` | All events from the Vagrant VM |
| `technique.keyword: T1190` | Exploitation events (network callbacks) |
| `technique.keyword: T1059.004` | Shell execution events |
| `host: dv-victim AND technique.keyword: T1068` | Privilege escalation on the VM |
| `proctitle: jndi OR cmd_output: jndi` | Free-text search for Log4Shell payloads |

Set the time range (top right) to cover your last attack run.

### Splunk mock UI

```
http://localhost:8000
```

Search: `index=* host=dv-victim | head 20`

### Direct API query

```bash
curl -sk -u admin:"$OPENSEARCH_INITIAL_ADMIN_PASSWORD" \
  "https://localhost:9200/dv-telemetry-*/_search?pretty&size=5&sort=timestamp:desc" \
  -H 'Content-Type: application/json' \
  -d '{"query": {"term": {"host.keyword": "dv-victim"}}}'
```

---

## CVE coverage analysis

This workflow answers: *"Do I have detections for the techniques an attacker would use to exploit this CVE?"*

```bash
# Step 1 — update local intelligence caches (ATT&CK STIX bundle, CISA KEV, NVD, EPSS)
dv intel update --source attack
dv intel update --source cve

# Step 2 — parse and normalize all detection rules
dv ingest examples/detections/ -o canonical.jsonl

# Step 3 — map rules to ATT&CK techniques
dv map -i canonical.jsonl -o mapped.jsonl --mode hybrid

# Step 4 — enrich with technique names, CVE metadata, and severity
dv enrich -i mapped.jsonl -o enriched.jsonl

# Step 5 — analyze coverage for a CVE
dv cve-coverage --cve CVE-2021-44228,CVE-2021-34527,CVE-2021-26855 \
  --detections enriched.jsonl
```

Sample output:

```
CVE-2021-44228  KEV  CVSS=10.0  EPSS=0.945  coverage=67%  residual_risk=3.149
  ✓ T1059  execution     conf=0.85  ← Log4Shell JNDI Injection Attempt
  ✓ T1190  initial-access conf=0.80  ← Log4Shell JNDI Injection Attempt
  ✗ T1499  impact        conf=0.60

CVE-2021-34527  KEV  CVSS=8.8   EPSS=0.942  coverage=0%   residual_risk=8.293
  (no techniques mapped — add explicit attack.TXXXX tags to your rules)
```

**Reading the output:**
- **KEV** — listed in CISA's Known Exploited Vulnerabilities catalog (actively exploited in the wild)
- **EPSS** — probability this CVE is exploited within 30 days (source: FIRST.org)
- **residual_risk** — `CVSS × EPSS × (1 − coverage_ratio)`; closer to 0 is better
- **conf** — mapping confidence (explicit rule tag = 1.0; CTID dataset ≈ 0.90; CWE inference = varies)

### Closing a coverage gap

If `cve-coverage` shows ✗ for a technique, add it to a detection rule:

```yaml
tags:
    - attack.T1499          # the uncovered technique
    - cve.2021.44228        # links this rule to the CVE in coverage reports
```

Then re-run `ingest → map → enrich → cve-coverage` to confirm the gap closes.

---

## ATT&CK Navigator export

Visualize which techniques your detections cover:

```bash
dv navigator -d enriched.jsonl -o coverage-layer.json
# Open https://mitre-attack.github.io/attack-navigator/
# → Open Existing Layer → Upload from local → select coverage-layer.json
```

---

## Example detection rules

Ready-to-use rules under `examples/detections/`:

| Format | File | CVE | Techniques |
|---|---|---|---|
| Sigma | `sigma/log4shell_jndi_injection.yml` | CVE-2021-44228 | T1190, T1059.004 |
| Sigma | `sigma/printnightmare_spooler_abuse.yml` | CVE-2021-34527 | T1068, T1547.012, T1574.001 |
| Sigma | `sigma/proxylogon_exchange_ssrf.yml` | CVE-2021-26855 | T1190, T1505.003, T1078 |
| Sigma | `sigma/credential_dump_lsass.yml` | — | T1003.001 |
| Sigma | `sigma/network_scan_nmap.yml` | — | T1046 |
| Splunk | `splunk/dns_beaconing.spl` | — | T1071.004 |
| KQL | `kql/sentinel_aad_password_spray.yml` | — | T1110.003 |
| Elastic EQL | `elastic/credential_access_mimikatz.json` | — | T1003 |

---

## Architecture

```
┌─ CLI ──────────────────────────────────────────────────────────┐
│  dv doctor       — pre-flight check: tools, containers, caches │
│  dv attack       — simulate CVE exploit steps on victim        │
│  dv validate     — query live SIEM, report PASS/FAIL per rule  │
│  dv match        — same evaluation offline against a JSONL file│
│  dv report       — render results as CLI / SARIF / HTML        │
│  dv ingest       — parse Sigma/Splunk/KQL/YARA/EQL to JSONL    │
│  dv map          — map rules to ATT&CK techniques              │
│  dv enrich       — fill technique names, CVE metadata, severity│
│  dv cve-coverage — analyze coverage gaps per CVE               │
│  dv navigator    — export ATT&CK Navigator layer               │
└──────────────────────────────────────────────────────────────────┘
         │
┌─ Telemetry pipeline ───────────────────────────────────────────┐
│                                                                  │
│  Vagrant VM (Ubuntu 22.04 ARM64)                                │
│    auditd → /var/log/audit/audit-events.jsonl                   │
│    victim-agent (port 9099) ← dv attack                         │
│    vector → OpenSearch (9200) + Splunk HEC (8088)               │
│                                                                  │
│  Docker victim (Linux, synthetic events)                        │
│    docker logs → vector → OpenSearch + Splunk HEC              │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
         │
┌─ SIEMs ────────────────────────────────────────────────────────┐
│  OpenSearch  localhost:9200   Dashboards: localhost:5601        │
│  Splunk mock localhost:8088   UI:         localhost:8000        │
└──────────────────────────────────────────────────────────────────┘
```

### Telemetry fields

Events written by the victim agent include:

| Field | Example | Description |
|---|---|---|
| `technique` | `T1190` | ATT&CK technique ID |
| `key` | `network_connect` | Audit rule that fired |
| `exe` | `/usr/bin/curl` | Process executable path |
| `uid` | `33` | UID of the process (33 = www-data) |
| `cmd_output` | `uid=0(root)...` | Command output captured |
| `host` | `dv-victim` | Source hostname |
| `cve` | `CVE-2021-44228` | CVE linked to the attack step |
| `timestamp` | `2026-05-25T09:04:03Z` | ISO 8601 UTC |

---

## Vagrant VM reference

```bash
cd vagrant

vagrant up          # create and provision VM (~5 min first time)
vagrant ssh         # shell into VM
vagrant halt        # stop VM
vagrant destroy -f  # remove VM entirely

# Re-run provisioning after changing files/
vagrant provision

# Check services inside the VM
vagrant ssh -c "systemctl status victim-agent vector auditd --no-pager"

# Watch audit events as they arrive
vagrant ssh -c "tail -f /var/log/audit/audit-events.jsonl"
```

The VM uses port 9098 (host) → 9099 (guest) for the victim agent, so it does not conflict with the Docker victim container (9099).

---

## Apple Silicon (M1/M2/M3/M4)

Fully supported. All core services run natively on ARM64.

| Component | ARM64 status |
|---|---|
| OpenSearch + Dashboards | ✅ native |
| Splunk mock (HEC) | ✅ native (Python) |
| Vagrant VM via QEMU/HVF | ✅ native ARM64 |
| Docker Linux victim | ✅ native |
| Splunk Enterprise | ❌ amd64-only — use the mock or `--siem opensearch` |

**OpenSearch fails with `vm.max_map_count too low`:**
```bash
docker run --rm --privileged alpine sysctl -w vm.max_map_count=262144
```

**Out of memory / containers restarting:**
```bash
# In Docker Desktop → Settings → Resources → Memory → set to ≥ 6 GB
./dv up lab --siem opensearch --profile tiny
```

**`dv` command not found:**
```bash
source .venv/bin/activate
which dv   # should point inside .venv/bin/
```

---

## Resource profiles

```bash
./dv up lab --profile tiny      # ≤1 GB RAM per service (recommended for 16 GB MacBook)
./dv up lab --profile standard  # 4 GB RAM per service
./dv up lab --profile full      # 8 GB+ RAM, all optional services
```

---

## GitHub Action

```yaml
jobs:
  validate:
    uses: your-org/detection-validator/.github/workflows/detection-validation.yml@main
    with:
      rules-path: detections/
      siem: opensearch
      output-format: sarif
```

Or as a composite action step:

```yaml
- uses: your-org/detection-validator/actions/validate@main
  with:
    rules-path: detections/
    siem: opensearch
```

---

## License

Apache 2.0
