# Detection Validator — Windows Setup Guide

This guide walks through setting up and running Detection Validator on **Windows 11** (amd64). It covers everything from installing prerequisites to running your first attack simulation and validation report.

For macOS, see the project [README](../README.md). The steps here are Windows-specific.

---

## What Windows gives you

Detection Validator on Windows runs the full lab stack inside Docker (WSL2 backend). You get:

- **Linux victim container** — runs synthetic audit events (no kernel access in Docker, so `auditd` falls back to a built-in emulator that generates realistic JSON telemetry)
- **OpenSearch** — the SIEM backend where telemetry lands
- **Vector** — the log shipper that moves events from victim to SIEM
- **Python CLI** (`dv`) — runs natively in PowerShell for attacks, validation, and reports

What you **don't** get on Windows vs Mac:

| Capability | Mac | Windows |
|---|---|---|
| Real kernel `auditd` events | ✓ via Vagrant VM | ✗ Docker can't attach to WSL2 audit subsystem |
| Real Vagrant VM telemetry | ✓ native QEMU/HVF | Limited — use Docker target instead |
| Full Splunk Enterprise | ✓ amd64 | ✓ amd64 (but requires more RAM) |
| Windows victim (Sysmon) | amd64 emulator only | ✓ native amd64 |

For most detection validation work — checking whether your Sigma rules fire on realistic audit events — the Docker-based synthetic mode is sufficient.

---

## Prerequisites

Install these in order. All are free.

### 1. Docker Desktop

Download from [docker.com/products/docker-desktop](https://www.docker.com/products/docker-desktop/).

During setup, leave the default **WSL 2 backend** selected. Do **not** switch to Windows containers mode.

After install, open Docker Desktop and wait until the whale icon in the taskbar shows "Docker Desktop is running".

> **Memory setting (important):** Go to Docker Desktop → Settings → Resources → Memory. Set it to at least **8 GB**. OpenSearch alone needs ~2 GB. If containers keep restarting, this is the first thing to check.

Verify Docker works:

```powershell
docker version
```

Expected: `Docker 29.x` or later.

### 2. Git

Download from [git-scm.com](https://git-scm.com/downloads). During installation:
- Accept the default to add Git Bash to your PATH
- Accept the default "Checkout as-is, commit as-is" line ending setting

Git ships Git Bash, which you'll use to run the `./dv` launcher script (a shell script that Docker Compose doesn't need PowerShell-compatible wrappers for).

Verify:

```powershell
git --version
```

### 3. Python 3.12

```powershell
winget install Python.Python.3.12 --accept-source-agreements --accept-package-agreements
```

Close and reopen your terminal after this finishes. Verify:

```powershell
python --version   # Python 3.12.x
```

> Python 3.13 also works. Python 3.11 or older does **not** work — the project requires 3.12+.

### 4. uv (Python package manager)

```powershell
winget install astral-sh.uv --accept-source-agreements --accept-package-agreements
```

Close and reopen your terminal. Verify:

```powershell
uv --version   # uv 0.11.x or later
```

### Summary checklist

```
✓ Docker Desktop 29+ (WSL2 backend, Linux containers mode)
✓ Git 2.x with Git Bash
✓ Python 3.12 or 3.13
✓ uv (any version)
```

Vagrant is **optional** on Windows. If you want real `auditd` kernel events (the highest-fidelity telemetry), see [Vagrant on Windows](#optional-vagrant-for-real-kernel-events) at the end of this guide. For everything else, Docker synthetic mode is sufficient.

---

## Installation

Run all of these in **PowerShell** unless noted otherwise. Open PowerShell as a regular user (not Administrator).

### 1. Clone the repository

```powershell
git clone https://github.com/saadabbasi-playground/detectionvalidation.git detection-validator
cd detection-validator
```

### 2. Fix line endings (Windows-only, one-time)

Git on Windows sometimes converts Unix line endings (LF) to Windows line endings (CRLF) in shell scripts. This breaks Docker containers that run those scripts on Linux. Run this once after cloning:

```powershell
$scripts = @("docker\linux-victim\entrypoint.sh", ".devcontainer\post-create.sh",
             "install.sh", "vagrant\provision.sh", "examples\validate-sigma.sh", "dv")
foreach ($f in $scripts) {
    if (Test-Path $f) {
        $c = [IO.File]::ReadAllText($f)
        [IO.File]::WriteAllText($f, ($c -replace "`r`n","`n" -replace "`r","`n"),
            [Text.UTF8Encoding]::new($false))
    }
}
Write-Host "Line endings fixed."
```

> **Why:** The `./dv` launcher and Docker entrypoint scripts must have LF endings. A CRLF shebang line (`#!/bin/bash\r`) causes Linux to look for an interpreter named `/bin/bash\r`, which doesn't exist, producing a cryptic "no such file or directory" error.
>
> The project now ships a `.gitattributes` file that prevents this on future clones. You only need this fix if you cloned before the `.gitattributes` was added.

### 3. Create the Python virtual environment

```powershell
uv venv
uv pip install -e ".[dev]"
```

This installs the `dv` CLI and all dependencies into `.venv\`.

### 4. Activate the virtual environment

```powershell
.\.venv\Scripts\Activate.ps1
```

If PowerShell blocks the script due to execution policy, run this first (once per machine):

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

After activation your prompt shows `(.venv)`. You now have `dv` on your PATH.

> **Every new terminal:** run `.\.venv\Scripts\Activate.ps1` before using `dv`. Or use the full path `.\.venv\Scripts\dv.exe` if you prefer not to activate.

### 5. Set the OpenSearch password

Set this once per terminal session — or add it to your PowerShell profile to avoid repeating it:

```powershell
$env:OPENSEARCH_INITIAL_ADMIN_PASSWORD = "DetectVal123!"
```

To persist across sessions, add it to your PowerShell profile:

```powershell
Add-Content $PROFILE '$env:OPENSEARCH_INITIAL_ADMIN_PASSWORD = "DetectVal123!"'
```

> **Note:** `DetectVal123!` is the default password for this local development environment only. It is not used for any external service.

### 6. Enable UTF-8 output (Windows-only)

The `dv` CLI uses Unicode symbols (✓ ✗ ⚠) in its output. Windows PowerShell defaults to a legacy codepage that can't display these. Add these two lines whenever you use `dv`, or add them to your PowerShell profile:

```powershell
$env:PYTHONUTF8 = "1"
$env:PYTHONIOENCODING = "utf-8"
chcp 65001 | Out-Null
```

To make this permanent, add all three lines to your PowerShell profile (`$PROFILE`).

---

## Step 1 — Check your environment

```powershell
dv doctor
```

Expected output on a clean Windows install:

```
dv doctor — environment pre-flight check

  ✓ Python 3.12.10
  ⚠ uv not found  install from https://docs.astral.sh/uv/
  ✓ Docker 29.4.3
  ✓ Docker daemon running
  ✓ Docker network detectval-lab   ← created in Step 2 below
  ⚠ Vagrant not found  install Vagrant + vagrant-qemu for real auditd telemetry
  ✓ OPENSEARCH_INITIAL_ADMIN_PASSWORD set
  ✗ OpenSearch not reachable   ← fixed after Step 2
  ...
```

**Expected Windows warnings (not errors):**

| Warning | Why | Action needed |
|---|---|---|
| `uv not found` | uv is installed but its PATH update requires a new terminal | Reopen terminal or run `winget install astral-sh.uv` again. The CLI works fine despite this warning — it's a path-lookup false negative. |
| `Vagrant not found` | Vagrant is optional on Windows | None unless you want real kernel events |
| `KEV cache empty` | Intel caches not downloaded yet | Run `dv intel update --source cve` (Step 1b) |
| `ATT&CK cache empty` | Same | Run `dv intel update --source attack` (Step 1b) |

Fix the two cache warnings before continuing:

```powershell
dv intel update --source attack
dv intel update --source cve
```

**If you see `UnicodeEncodeError`** in the output, you missed the UTF-8 step above. Set `$env:PYTHONUTF8 = "1"` and re-run.

---

## Step 2 — Start the Docker stack

The `./dv` launcher is a Bash script. Run it from **Git Bash** (not PowerShell).

Open Git Bash and navigate to the project directory:

```bash
cd /c/path/to/detection-validator   # adjust to your actual path
```

Create the Docker network (one-time setup):

```bash
docker network create detectval-lab
```

Start the lab stack:

```bash
OPENSEARCH_INITIAL_ADMIN_PASSWORD="DetectVal123!" bash ./dv up lab --siem opensearch --profile standard
```

> **Why Git Bash?** The `./dv` script uses Bash syntax (`set -euo pipefail`, `IFS`, arrays) that PowerShell can't run. Git Bash ships a full Bash interpreter. You only need Git Bash for `./dv up` and `./dv down` — all other `dv` commands run fine in PowerShell.

Wait about 60–90 seconds for all images to download and containers to start. Then check status:

```bash
docker ps --format "table {{.Names}}\t{{.Status}}"
```

Expected (standard profile):

```
NAMES                STATUS
dv-linux-victim      Up 2 minutes (healthy)
dv-vector            Up 2 minutes (healthy)
dv-opensearch        Up 2 minutes (healthy)
dv-redis             Up 2 minutes (healthy)
```

Every container must say `(healthy)`. If one says `(starting)`, wait another 30 seconds and check again.

> **If `dv-linux-victim` says "Restarting"** and logs show `exec /entrypoint.sh: no such file or directory`: this is the CRLF line-endings problem. Run the fix in Step 2 of Installation, rebuild the image, and restart the container:
> ```powershell
> docker build -t detection-validator/linux-victim:dev -f docker/linux-victim/Dockerfile docker/linux-victim/
> docker rm -f dv-linux-victim
> docker compose -f compose/docker-compose.yml -f compose/docker-compose.lab.yml -f compose/siem/opensearch.yml up -d linux-victim
> ```

Switch back to **PowerShell** for all remaining steps.

Verify OpenSearch is running:

```powershell
dv siem status
```

Expected:

```
✓ OpenSearch 2.14.0  at https://localhost:9200
  dv-telemetry-*: 0 documents
```

---

## Step 3 — Run an attack simulation

```powershell
dv attack --cve CVE-2021-44228 --target docker --mode simulate
```

`--target docker` uses the local `dv-linux-victim` container (not a Vagrant VM). `--mode simulate` posts synthetic audit records directly to the victim agent — no real exploit is sent.

Expected output:

```
⚔  Running attack scenario  cve=CVE-2021-44228  target=docker

▶ Log4Shell Remote Code Execution  CVE: CVE-2021-44228

✓ Victim agent ready at http://dv-linux-victim:9099

Step 1/2 [T1190] Send HTTP request with JNDI injection payload in header
  → Simulate Log4Shell JNDI injection HTTP request
    ✓  rc=0
Step 2/2 [T1059.004] Shell spawned from web process context (uid=33 www-data)
  → Shell spawned from web process context (uid 33 = www-data)
    ✓  rc=0  uid=0(root) gid=0(root) groups=0(root)

Scenario complete. 2 steps executed.
Events are flowing to OpenSearch and Splunk via Vector.
```

> **Platform warning in output:** You may see `WARNING: The requested image's platform (linux/arm64) does not match the detected host platform (linux/amd64)`. This is cosmetic — the container runs fine under Docker's emulation layer and has no impact on the telemetry.

Run all three built-in CVE scenarios for full coverage:

```powershell
dv attack --cve CVE-2021-44228 --target docker --mode simulate   # Log4Shell
dv attack --cve CVE-2021-34527 --target docker --mode simulate   # PrintNightmare
dv attack --cve CVE-2021-26855 --target docker --mode simulate   # ProxyLogon
```

Verify events landed in OpenSearch (allow 10–15 seconds for Vector to flush):

```powershell
dv siem status
# Expected: dv-telemetry-*: 30+ documents
```

---

## Step 4 — Validate your detections

```powershell
dv validate examples/detections/sigma/ --since 1
```

Expected output after all three CVE scenarios:

```
 Rule                     Techniques               Hits  Source       Status
 LSASS Memory Dump        T1003.001                   0  opensearch   ✗ FAIL
 Log4Shell JNDI           T1190, T1059.004            4  opensearch   ✓ PASS
 Log4Shell RCE - Outbound T1190, T1059.004            4  opensearch   ✓ PASS
 MSHTA Spawning Windows   T1218.005, T1059.001        0  opensearch   ✗ FAIL
 Nmap Port Scan Detected  T1046                       0  opensearch   ✗ FAIL
 PrintNightmare Spooler   T1068, T1547.012            4  opensearch   ✓ PASS
 ProxyLogon Exchange SSRF T1190, T1505.003            4  opensearch   ✓ PASS
 ProxyLogon Sensitive File T1190, T1552.001           3  opensearch   ✓ PASS

Results: 8 rule(s)  5 PASS  3 FAIL  0 ERROR  0 SKIP  (1.2s)
```

**Why 3 rules fail — this is expected:**

| Rule | Reason |
|---|---|
| LSASS Memory Dump | Targets `lsass.exe` — a Windows-only process. The Linux victim never generates this event. |
| MSHTA Spawning Windows Shell | Same — MSHTA is a Windows binary. |
| Nmap Port Scan | Requires an active Nmap scan to be run against the victim. Not included in the default scenarios. |

---

## Step 5 — Generate a report

Save results and render as HTML:

```powershell
dv validate examples/detections/sigma/ --since 1 --format json -o results.json
dv report --results results.json --format html -o report.html
Start-Process report.html   # opens in your default browser
```

Or generate a CLI summary:

```powershell
dv report --results results.json
```

Or SARIF for GitHub Code Scanning:

```powershell
dv report --results results.json --format sarif -o scan.sarif
```

---

## Step 6 — Offline matching (no SIEM needed)

Export events from OpenSearch and match rules against them locally — no running containers required:

```bash
# In Git Bash — PowerShell's curl doesn't support -k for TLS skip
curl -sk -u "admin:DetectVal123!" \
  "https://localhost:9200/dv-telemetry-*/_search?size=500" \
  -H "Content-Type: application/json" \
  -d '{"query":{"term":{"source":"auditd-agent"}}}' \
  | python3 -c "
import json, sys
for h in json.load(sys.stdin)['hits']['hits']:
    print(json.dumps(h['_source']))
" > events.jsonl
```

Then in PowerShell:

```powershell
dv match --events events.jsonl examples/detections/sigma/ --since 0 --format json | dv report
```

`--since 0` means "use all events regardless of timestamp". This runs entirely in memory — no network calls — and typically completes in under 0.1 seconds.

---

## Connecting to an external SIEM (Splunk or Elastic)

By default, `dv` ships telemetry to the local OpenSearch container and validates against it. You can point it at any existing Splunk or Elasticsearch instance instead — on-prem or cloud.

There are two independent concerns:
- **Validating rules** — querying your SIEM for rule hits (`dv validate --siem <name>`)
- **Shipping telemetry** — routing attack events from Vector to your SIEM so there is something to query

Both require registering the SIEM first.

---

### Step A — Register the SIEM

Credentials are stored locally in `~/.detectionvalidator/siems.yaml` and never touch the project directory. Re-running `dv siem add` with the same name replaces the entry.

#### Splunk (on-prem)

Splunk needs two things enabled: the **HTTP Event Collector (HEC)** for ingesting events, and the **REST API** for querying.

1. In Splunk Web → Settings → Data Inputs → HTTP Event Collector → Global Settings: enable HEC and note the port (default `8088`).
2. Create a new HEC token. Copy the token value.
3. Note your Splunk management port (default `8089`).

Register with the **management port** URL — `dv siem test` and `dv validate` use the REST API:

```powershell
dv siem add splunk-prod `
    --type splunk `
    --url https://splunk.example.com:8089 `
    --token YOUR_HEC_TOKEN `
    --no-verify-tls
```

> **On-prem TLS note:** If your Splunk instance uses a self-signed certificate, include `--no-verify-tls`. For a trusted cert, omit it.

#### Splunk Cloud

Splunk Cloud HEC endpoints follow the format `input-<stack>.cloud.splunk.com:8088`. The REST API is at `<stack>.splunkcloud.com:8089`.

```powershell
dv siem add splunk-cloud `
    --type splunk `
    --url https://your-stack.splunkcloud.com:8089 `
    --token YOUR_HEC_TOKEN
```

#### Elasticsearch (on-prem)

```powershell
dv siem add elastic-prod `
    --type elasticsearch `
    --url https://elastic.example.com:9200 `
    --username elastic `
    --password YOUR_PASSWORD `
    --no-verify-tls
```

#### Elastic Cloud

Get the **Elasticsearch endpoint** from your Elastic Cloud deployment page (Kibana → Management → Copy endpoint). Create an API key under Stack Management → API Keys.

```powershell
dv siem add elastic-cloud `
    --type elasticsearch `
    --url https://my-deployment.es.us-east-1.aws.elastic.co:9243 `
    --api-key YOUR_API_KEY_HERE
```

> **Index pattern:** By default `dv` queries `dv-telemetry-*`. If your telemetry lands under a different index or data stream (e.g. `logs-*`, `winlogbeat-*`), override it:
> ```powershell
> dv siem add elastic-cloud --type elasticsearch --url ... --api-key ... --index "logs-*"
> ```

---

### Step B — Verify connectivity

```powershell
# List all registered SIEMs
dv siem list

# Test a specific connection — checks auth and returns cluster info
dv siem test splunk-prod
dv siem test elastic-cloud
```

Expected for Splunk:
```
✓ splunk-prod  Splunk build=9XXXX  url=https://splunk.example.com:8089
```

Expected for Elastic:
```
✓ elastic-cloud  cluster_status=green  nodes=3  url=https://...elastic.co:9243
  logs-*: 1,234,567 documents
```

---

### Step C — Ship telemetry to the external SIEM

Attack events need to reach your external SIEM before you can validate against it. How you do this depends on whether you are using Vagrant or Docker.

#### With Vagrant (macOS / Windows with Hyper-V)

`dv siem attach` SSHes into the Vagrant VM and adds a new Vector output sink. The local OpenSearch pipeline keeps running — `attach` only adds a second destination:

```powershell
dv siem attach splunk-prod
dv siem attach elastic-cloud
```

This modifies `/etc/vector/vector.toml` inside the VM and restarts Vector. Run attacks as normal — events flow to both your local OpenSearch and the external SIEM simultaneously.

#### With Docker on Windows (manual Vector config)

`dv siem attach` requires SSH access to the Vagrant VM, so it does not work in the Docker-only setup. Instead, add the sink directly to `configs/vector.toml` and restart the Vector container.

**For Splunk:** add this block to `configs/vector.toml` (adjust the endpoint and token):

```toml
[sinks.splunk_external]
type = "splunk_hec_logs"
inputs = ["parse_sysmon"]
endpoint = "https://splunk.example.com:8088"   # HEC port, not management port
token = "YOUR_HEC_TOKEN"
index = "main"

  [sinks.splunk_external.encoding]
  codec = "json"

  [sinks.splunk_external.acknowledgements]
  enabled = false

  [sinks.splunk_external.tls]
  verify_certificate = false   # set true if your cert is trusted
```

**For Elasticsearch / Elastic Cloud:** add this block to `configs/vector.toml`:

```toml
[sinks.elastic_external]
type = "elasticsearch"
inputs = ["parse_sysmon"]
endpoints = ["https://my-deployment.es.us-east-1.aws.elastic.co:9243"]
mode = "bulk"
suppress_type_name = true
api_version = "v8"

  [sinks.elastic_external.auth]
  strategy = "basic"
  # For API key auth, use: strategy = "aws" is wrong — use the header approach below

  [sinks.elastic_external.bulk]
  index = "dv-telemetry-%Y.%m.%d"

  [sinks.elastic_external.request.headers]
  Authorization = "ApiKey YOUR_API_KEY_HERE"

  [sinks.elastic_external.tls]
  verify_certificate = true
```

> **For basic auth instead of API key**, replace the `[sinks.elastic_external.auth]` and `[sinks.elastic_external.request.headers]` blocks with:
> ```toml
>   [sinks.elastic_external.auth]
>   strategy = "basic"
>   user = "elastic"
>   password = "YOUR_PASSWORD"
> ```

After editing `configs/vector.toml`, restart Vector to apply the change:

```powershell
docker restart dv-vector
docker logs dv-vector --tail 20 2>&1 | Select-String "ERROR|WARN"
```

If Vector logs show no errors for the new sink, telemetry is flowing. Run an attack and verify:

```powershell
dv siem test elastic-cloud   # or splunk-prod
```

---

### Step D — Validate rules against the external SIEM

Pass the registered name to `--siem`:

```powershell
dv validate examples/detections/sigma/ --siem elastic-cloud --since 1
dv validate examples/detections/sigma/ --siem splunk-prod --since 1
```

The validator translates each Sigma rule into the native query language, runs it against your SIEM, and reports PASS/FAIL exactly as it does for local OpenSearch.

> **Splunk note:** `dv validate --siem splunk-prod` uses the Splunk REST search API (port 8089). This is separate from HEC (port 8088), which is write-only. Make sure your registered URL points to the management port (8089), not the HEC port (8088).

Save and report as normal:

```powershell
dv validate examples/detections/sigma/ --siem elastic-cloud --since 24 --format json -o results.json
dv report --results results.json --format html -o report.html
```

---

### External SIEM quick reference

| Task | Splunk | Elastic |
|---|---|---|
| Register | `dv siem add NAME --type splunk --url https://host:8089 --token TOKEN` | `dv siem add NAME --type elasticsearch --url https://host:9200 --api-key KEY` |
| Test connection | `dv siem test NAME` | `dv siem test NAME` |
| Ship telemetry (Vagrant) | `dv siem attach NAME` | `dv siem attach NAME` |
| Ship telemetry (Docker) | Add `splunk_hec_logs` sink to `configs/vector.toml`, use HEC port 8088 | Add `elasticsearch` sink to `configs/vector.toml` |
| Validate rules | `dv validate detections/ --siem NAME --since 1` | `dv validate detections/ --siem NAME --since 1` |

---

## Stopping the stack

In Git Bash:

```bash
bash ./dv down lab --siem opensearch
```

Or stop individual containers:

```powershell
docker stop dv-opensearch dv-linux-victim dv-vector dv-redis
```

---

## Troubleshooting

### `UnicodeEncodeError: 'charmap' codec can't encode character`

Windows PowerShell defaults to codepage 1252, which can't display Unicode symbols. Fix:

```powershell
$env:PYTHONUTF8 = "1"
$env:PYTHONIOENCODING = "utf-8"
chcp 65001 | Out-Null
```

Add these three lines to your PowerShell profile (`$PROFILE`) to make it permanent.

### `exec /entrypoint.sh: no such file or directory`

The `dv-linux-victim` container's entrypoint has CRLF line endings. Fix:

```powershell
$f = "docker\linux-victim\entrypoint.sh"
$c = [IO.File]::ReadAllText($f)
[IO.File]::WriteAllText($f, ($c -replace "`r`n","`n"), [Text.UTF8Encoding]::new($false))
docker build -t detection-validator/linux-victim:dev -f docker/linux-victim/Dockerfile docker/linux-victim/
docker rm -f dv-linux-victim
docker compose -f compose/docker-compose.yml -f compose/docker-compose.lab.yml -f compose/siem/opensearch.yml up -d linux-victim
```

### `dv validate` returns 0 hits for all rules

Check two things:

**1. Are there events in OpenSearch?**

```powershell
dv siem status
```

If the document count is 0, wait 15 more seconds and check again. Vector batches events before flushing.

**2. Is the time window wide enough?**

`--since 1` looks back 1 hour. If you ran attacks earlier, extend the window:

```powershell
dv validate examples/detections/sigma/ --since 24
```

**3. Check Vector logs for mapping errors:**

```powershell
docker logs dv-vector --tail 20 2>&1 | Select-String "ERROR"
```

If you see `can't merge a non object mapping [label.com.docker.compose.project]`, the OpenSearch index has a stale mapping. Fix:

```bash
# In Git Bash
curl -sk -X DELETE -u "admin:DetectVal123!" "https://localhost:9200/dv-telemetry-$(Get-Date -Format 'yyyy.MM.dd')"
docker restart dv-vector
```

Then re-run the attacks and validate.

### `dv doctor` says "OpenSearch auth failed"

```powershell
$env:OPENSEARCH_INITIAL_ADMIN_PASSWORD = "DetectVal123!"
dv siem status
```

The password in your environment must match the password OpenSearch was started with.

### OpenSearch container fails to start — `vm.max_map_count too low`

```powershell
docker run --rm --privileged alpine sysctl -w vm.max_map_count=262144
```

Then restart the stack.

### Containers keep restarting due to memory

In Docker Desktop → Settings → Resources → Memory: set to at least **8 GB**. Then use the `tiny` profile:

```bash
bash ./dv down lab --siem opensearch
bash ./dv up lab --siem opensearch --profile tiny
```

### `./dv` command not found or syntax error in PowerShell

The `./dv` launcher is a Bash script and **cannot run in PowerShell**. Open Git Bash and run it there:

```bash
bash ./dv up lab --siem opensearch --profile standard
```

---

## Optional: Vagrant for real kernel events

> **Skip this section** unless you specifically need genuine `auditd` syscall events rather than synthetic ones. For most rule-validation work, Docker synthetic mode is sufficient.

Vagrant on Windows requires **Hyper-V** (built into Windows 10/11 Pro and Enterprise) or **VirtualBox**. The QEMU-based setup used on Mac does not work on Windows.

### With Hyper-V (Windows Pro/Enterprise only)

1. Enable Hyper-V: `Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All`
2. Reboot
3. Install Vagrant: `winget install HashiCorp.Vagrant`
4. The default Vagrant provider on Windows is Hyper-V — no extra plugin needed

```powershell
cd vagrant
vagrant up    # uses Hyper-V automatically
vagrant ssh -c "systemctl status victim-agent vector --no-pager"
```

Verify the agent is reachable:

```powershell
curl http://localhost:9098/health
```

Then run attacks against the VM target:

```powershell
dv attack --cve CVE-2021-44228 --target vagrant --mode exploit
```

### Known limitations with Vagrant on Windows

- Vagrant with Hyper-V runs as Administrator. You will be prompted for elevation when running `vagrant up`.
- Hyper-V and VirtualBox cannot run at the same time. If you have VirtualBox installed, use `--provider virtualbox` and adjust the `Vagrantfile` to use a VirtualBox-compatible box.
- The `vagrant-qemu` plugin is macOS-only. Do not install it on Windows.

---

## Port reference (Windows host)

| Port | What uses it | Notes |
|---|---|---|
| `9200` | OpenSearch API | Used by `dv validate`, `dv siem status` |
| `5601` | OpenSearch Dashboards | Open in browser after `./dv up` with dashboards profile |
| `9099` | Linux victim agent (Docker) | Used by `dv attack --target docker` |
| `9098` | Linux victim agent (Vagrant VM) | Only if Vagrant is running |
| `9088` | Vulnerable service (Vagrant VM) | Needed for `--mode exploit` |
| `8686` | Vector API | Internal health check |

---

## Environment variable reference

| Variable | Required | Description |
|---|---|---|
| `OPENSEARCH_INITIAL_ADMIN_PASSWORD` | Yes | OpenSearch admin password. Must match what the container was started with. |
| `PYTHONUTF8` | Yes (Windows) | Set to `1` to enable UTF-8 mode. Prevents Unicode errors in the CLI output. |
| `PYTHONIOENCODING` | Yes (Windows) | Set to `utf-8`. Works alongside `PYTHONUTF8`. |
| `DV_LOG_LEVEL` | No | Set to `DEBUG` for verbose logging. Default: `INFO`. |

---

## Quick-reference command table

All `dv` commands run in **PowerShell** (with venv activated and UTF-8 env vars set). The `./dv` launcher runs in **Git Bash**.

| Task | Command | Shell |
|---|---|---|
| Start the lab stack | `bash ./dv up lab --siem opensearch --profile standard` | Git Bash |
| Stop the lab stack | `bash ./dv down lab --siem opensearch` | Git Bash |
| Check stack status | `docker ps --format "table {{.Names}}\t{{.Status}}"` | Either |
| Pre-flight check | `dv doctor` | PowerShell |
| Update intel caches | `dv intel update --source attack && dv intel update --source cve` | PowerShell |
| Run Log4Shell simulation | `dv attack --cve CVE-2021-44228 --target docker --mode simulate` | PowerShell |
| Run all 3 CVE scenarios | (run attack command 3 times with different CVEs) | PowerShell |
| Validate Sigma rules | `dv validate examples/detections/sigma/ --since 1` | PowerShell |
| Save results to JSON | `dv validate examples/detections/sigma/ --since 1 --format json -o results.json` | PowerShell |
| Generate HTML report | `dv report --results results.json --format html -o report.html` | PowerShell |
| Check SIEM + doc count | `dv siem status` | PowerShell |
| Offline rule match | `dv match --events events.jsonl examples/detections/sigma/ --since 0` | PowerShell |
