# Quickstart — Mac Apple Silicon (M1 / M2 / M3 / M4)

This guide takes you from a blank Mac to a running attack simulation, step by step. Every command is exact. Nothing is assumed.

---

## What you will end up with

- OpenSearch running in Docker (your SIEM — stores attack telemetry)
- A Ubuntu 22.04 ARM64 virtual machine (the victim — generates real Linux audit events)
- The `dv` CLI installed and working
- A simulated CVE attack executed against the VM
- A validation report showing which detection rules fired

---

## Understanding the two `dv` commands

There are two separate tools in this project that are both invoked as `dv`. They do different things:

| Command | What it is | What it does |
|---|---|---|
| `./dv` | Shell script (`./dv` in project root) | Starts and stops Docker containers |
| `dv` | Python CLI (installed via `uv pip install`) | Runs attacks, validates rules, generates reports |

**Rule:** use `./dv up` and `./dv down` to manage Docker. Use `dv doctor`, `dv attack`, `dv validate` etc. for everything else. The `dv` Python CLI only works after you run `source .venv/bin/activate`.

---

## Part 1 — Install prerequisites

Open **Terminal** and run each block in order. Do not skip anything.

### 1.1 Install Homebrew

```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

After it finishes, follow any instructions it prints about adding Homebrew to your PATH. Then close Terminal and open a new one.

Verify it worked:

```bash
brew --version
```

You should see something like `Homebrew 4.x.x`. If you get `command not found`, the PATH setup step was missed — re-read the instructions Homebrew printed.

---

### 1.2 Install Python 3.12

```bash
brew install python@3.12
```

Verify:

```bash
python3.12 --version
```

Expected: `Python 3.12.x`

---

### 1.3 Install uv (Python package manager)

```bash
brew install uv
```

Verify:

```bash
uv --version
```

Expected: `uv 0.x.x`

---

### 1.4 Install Docker Desktop

Download Docker Desktop for Mac — **Apple Silicon version**:
**https://www.docker.com/products/docker-desktop/**

Install it like any Mac app (drag to Applications). Open Docker Desktop from your Applications folder and wait for the whale icon in the menu bar to stop animating. That means Docker is running.

Give Docker Desktop enough memory — it needs at least 6 GB:

1. Open Docker Desktop
2. Click the gear icon (top right) → **Resources** → **Memory**
3. Drag the slider to **6 GB** or more
4. Click **Apply & Restart**

Verify Docker is running:

```bash
docker --version
docker ps
```

`docker ps` should return an empty table with no error. If you see `Cannot connect to the Docker daemon`, Docker Desktop is not running — open it from Applications.

---

### 1.5 Install Vagrant

```bash
brew install vagrant
```

Verify:

```bash
vagrant --version
```

Expected: `Vagrant 2.x.x`

---

### 1.6 Install QEMU and the vagrant-qemu plugin

QEMU provides the `qemu-img` tool that vagrant-qemu needs to import VM disk images.

```bash
brew install qemu
```

Verify:

```bash
qemu-img --version
```

Expected: `qemu-img version 9.x.x` (or similar).

Then install the Vagrant plugin that connects Vagrant to QEMU:

```bash
vagrant plugin install vagrant-qemu
```

Verify:

```bash
vagrant plugin list
```

You should see `vagrant-qemu` in the list.

---

## Part 2 — Clone and install the project

### 2.1 Clone the repository

```bash
git clone https://github.com/saadabbasi-playground/detectionvalidation.git detection-validator
cd detection-validator
```

All commands from here on are run from inside the `detection-validator/` directory unless told otherwise.

---

### 2.2 Create the Python virtual environment

```bash
uv venv
```

This creates a `.venv/` folder inside the project directory.

---

### 2.3 Install the Python package

```bash
uv pip install -e ".[dev]"
```

This installs the `dv` CLI tool and all its dependencies. Takes about 30–60 seconds.

---

### 2.4 Activate the virtual environment

```bash
source .venv/bin/activate
```

Your terminal prompt will change — it will show `(detection-validator)` at the beginning. This means the environment is active and the `dv` command is available.

> **Every time you open a new Terminal window**, you must run `source .venv/bin/activate` again before using `dv`.
>
> If you see `dv: command not found`, work through this checklist:
>
> 1. Activate the venv: `source .venv/bin/activate`
> 2. If still not found, the package isn't installed yet: `uv pip install -e ".[dev]"`
> 3. Verify it works: `dv --help`

Verify the CLI works:

```bash
dv --help
```

You should see a list of commands.

---

### 2.5 Create the Docker network

The lab requires a Docker network called `detectval-lab`. Create it now:

```bash
docker network create detectval-lab
```

If it already exists you will see `Error response from daemon: network with name detectval-lab already exists` — that is fine, ignore it.

---

### 2.6 Save the OpenSearch password permanently

The lab uses `DetectVal123!` as the OpenSearch admin password. Add it to your shell profile so you never have to type it again:

```bash
echo 'export OPENSEARCH_INITIAL_ADMIN_PASSWORD="DetectVal123!"' >> ~/.zshrc
source ~/.zshrc
```

Verify:

```bash
echo $OPENSEARCH_INITIAL_ADMIN_PASSWORD
```

Expected output: `DetectVal123!`

---

## Part 3 — Run the pre-flight check

```bash
dv doctor
```

This checks your entire environment before you waste time debugging. At this point, some warnings are expected because Docker containers are not running yet. You should see:

```
dv doctor — environment pre-flight check

  ✓ Python 3.12.5
  ✓ uv 0.11.13
  ✓ Docker 28.x.x
  ✓ Docker daemon running
  ✓ Docker network detectval-lab
  ✓ Vagrant 2.x.x
  ✓ Vagrant plugin vagrant-qemu
  ⚠ Vagrant VM not running          ← expected — VM not started yet
  ✓ OPENSEARCH_INITIAL_ADMIN_PASSWORD set
  ⚠ OpenSearch not reachable        ← expected — Docker stack not started yet
  ...
```

Fix any ✗ (red) errors before continuing. ⚠ (yellow) warnings are fine for now.

---

## Part 4 — Start the Docker stack

```bash
./dv up lab --siem opensearch --profile tiny
```

> `--profile tiny` keeps memory usage to ~600 MB per service. Recommended for all 16 GB MacBooks. Use `--profile standard` only if you have 32 GB and Docker Desktop is set to 12+ GB.

**First run** builds Docker images from source — takes 3–5 minutes. You will see build output scrolling. Subsequent starts take about 30 seconds.

Wait until you see `[dv] Stack 'lab' is running.` then check:

```bash
docker ps --format "table {{.Names}}\t{{.Status}}"
```

Wait for every container to say `(healthy)`. It can take up to 90 seconds after start for OpenSearch to become healthy.

Expected:

```
NAMES                          STATUS
dv-linux-victim                Up 2 minutes (healthy)
dv-vector                      Up 2 minutes (healthy)
dv-opensearch                  Up 2 minutes (healthy)
dv-opensearch-dashboards       Up 2 minutes (healthy)
detectval-splunk               Up 2 minutes (healthy)
```

If any container shows `(starting)`, wait 30 more seconds and run `docker ps` again.

Confirm OpenSearch is accepting connections:

```bash
dv siem status
```

Expected:

```
✓ OpenSearch 2.14.0  at https://localhost:9200
  dv-telemetry-*: 0 documents
```

If you see `auth failed`, make sure the password is set:

```bash
echo $OPENSEARCH_INITIAL_ADMIN_PASSWORD
```

It must print `DetectVal123!`. If it is empty, run `source ~/.zshrc`.

---

## Part 5 — Start the Vagrant VM

The Vagrant VM runs a real Ubuntu 22.04 ARM64 kernel with `auditd`. This generates genuine kernel-level syscall telemetry — the kind that detection rules need to fire against.

> **Important:** `vagrant` commands only work from inside the `vagrant/` directory. Always `cd vagrant` first.

```bash
cd vagrant
vagrant up
```

**First run:** downloads the Ubuntu ARM64 box (~500 MB) and provisions the VM. Takes about 5 minutes. You will see a lot of output — that is normal.

**Subsequent runs:** takes about 30 seconds.

When provisioning finishes, verify the three services inside the VM are running:

```bash
vagrant ssh -c "systemctl is-active victim-agent vector auditd"
```

Expected — three lines each saying `active`:

```
active
active
active
```

Verify the victim agent is reachable from your Mac:

```bash
curl http://localhost:9098/health
```

Expected:

```json
{"status": "ok", "host": "dv-victim", "mode": "vm"}
```

If you get `Connection refused`, wait 10 seconds and try again — the agent may still be starting.

Go back to the project root:

```bash
cd ..
```

---

## Part 6 — Final pre-flight check

Now that everything is running, re-run `dv doctor`:

> **Important:** there are two `doctor` commands — make sure you run the right one:
> - `./dv doctor` — shell script, checks Docker/infrastructure only
> - `dv doctor` — Python CLI, checks everything including Vagrant, ATT&CK KB, and KEV cache
>
> The venv must be active for `dv doctor` to work. If you see `command not found`, run `source .venv/bin/activate` first.

```bash
source .venv/bin/activate
dv doctor
```

Expected — all green except the KEV cache warning:

```
dv doctor — environment pre-flight check

  ✓ Python 3.12.5
  ✓ uv 0.11.13
  ✓ Docker 28.x.x
  ✓ Docker daemon running
  ✓ Docker network detectval-lab
  ✓ Vagrant 2.x.x
  ✓ Vagrant plugin vagrant-qemu
  ✓ Vagrant VM running
  ✓ OPENSEARCH_INITIAL_ADMIN_PASSWORD set
  ✓ OpenSearch reachable (HTTP 200)
  ✓ Splunk mock reachable (HTTP 200)
  ✓ Victim agent reachable on port 9098 (Vagrant)
  ✓ ATT&CK KB: 858 techniques
  ⚠ KEV cache empty
```

Fix the KEV cache warning by downloading threat intelligence data (the `--fix` flag does both in one step):

```bash
dv doctor --fix
```

Or download each source individually:

```bash
dv intel update --source attack   # MITRE ATT&CK — 858 techniques
dv intel update --source cve      # CISA KEV + EPSS risk scores
```

Run `dv doctor` one more time to confirm everything is green.

---

## Part 7 — Simulate attacks

Two modes are available. Use `--mode exploit` for the most realistic telemetry (real kernel-level events), or the default simulate mode for lightweight synthetic events.

### Option A — Real exploit (recommended)

Sends actual HTTP payloads to the intentionally vulnerable service on port 8888. The service runs `curl`, `id`, and reads `/etc/passwd` — all captured as real auditd syscall events.

First verify the vulnerable service is up:

```bash
curl http://localhost:8888/health
# Expected: {"status": "vulnerable"}
```

Then run the exploits:

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

### Option B — Simulate (synthetic events)

```bash
dv attack --cve CVE-2021-44228 --target vagrant --agent-port 9098 --watch
dv attack --cve CVE-2021-34527 --target vagrant --agent-port 9098 --watch
dv attack --cve CVE-2021-26855 --target vagrant --agent-port 9098 --watch
```

---

## Part 8 — Validate detections

```bash
dv validate examples/detections/sigma/ --since 1
```

This loads every detection rule, queries OpenSearch for matching events from the last hour, and reports PASS or FAIL:

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

> **Why do 2 rules fail?** LSASS targets a Windows process — never generated on Linux. Nmap requires an active port scan to be run. Both are expected.

If `--since 1` shows 0 hits for everything, extend the window:

```bash
dv validate examples/detections/sigma/ --since 24
```

---

## Part 9 — Generate reports

### CLI report (terminal)

```bash
dv validate examples/detections/sigma/ --since 1 --format json | dv report
```

> **How the pipe works:** `dv validate` writes its progress to the terminal (stderr) and the JSON results to the pipe (stdout). `dv report` reads from the pipe. No special flags needed.

### HTML report (open in browser)

```bash
dv validate examples/detections/sigma/ --since 1 --format json | dv report --format html -o report.html
open report.html
```

### SARIF report (for GitHub Code Scanning)

```bash
dv validate examples/detections/sigma/ --since 1 --format json | dv report --format sarif -o scan.sarif
```

---

## Part 10 — View live telemetry

### OpenSearch Dashboards

Open in your browser:

```
https://localhost:5601
```

Your browser will warn about an invalid certificate — click **Advanced** → **Proceed to localhost**. The certificate is self-signed for local use.

Log in:
- **Username:** `admin`
- **Password:** `DetectVal123!`

Then: hamburger menu (top left) → **Discover** → select `dv-telemetry-*` index → set time range to **Last 1 hour**.

Useful search queries:

| Query | What it shows |
|---|---|
| `technique: T1190` | Network exploitation events |
| `technique: T1068` | Privilege escalation events |
| `technique: T1059.004` | Shell execution events |
| `key: shell_exec` | All shell audit records |

### Inside the VM

```bash
cd vagrant
vagrant ssh
```

You are now inside the Ubuntu VM. Run:

```bash
# Watch events arrive in real time (Ctrl+C to stop)
sudo tail -f /var/log/audit/audit-events.jsonl

# Check services
systemctl status victim-agent vector auditd

# Exit back to Mac
exit
```

---

## Part 11 — Stop everything

```bash
# Stop VM (preserves state — fast to restart)
cd vagrant && vagrant halt && cd ..

# Stop Docker stack
./dv down lab --siem opensearch
```

---

## Daily workflow (after first-time setup)

Every subsequent session is just:

```bash
# Open Terminal, go to project, activate venv
cd detection-validator
source .venv/bin/activate

# Start Docker
./dv up lab --siem opensearch --profile tiny

# Start VM
cd vagrant && vagrant up && cd ..

# Check everything
dv doctor

# Run attack(s)
dv attack --cve CVE-2021-44228 --target vagrant --agent-port 9098 --watch

# Validate and report
dv validate examples/detections/sigma/ --since 1 --format json | dv report --format html -o report.html
open report.html
```

---

## Troubleshooting

### `dv: command not found`

The virtual environment is not active. Run:

```bash
source .venv/bin/activate
```

This must be done in every new Terminal window.

---

### `dv siem status` shows auth failed

The password environment variable is missing or wrong. Run:

```bash
source ~/.zshrc
echo $OPENSEARCH_INITIAL_ADMIN_PASSWORD
```

It must print `DetectVal123!`. If the file doesn't have it:

```bash
echo 'export OPENSEARCH_INITIAL_ADMIN_PASSWORD="DetectVal123!"' >> ~/.zshrc
source ~/.zshrc
```

---

### Docker containers not healthy / OpenSearch fails to start

**vm.max_map_count too low** — run this once:

```bash
docker run --rm --privileged alpine sysctl -w vm.max_map_count=262144
```

Then restart the stack:

```bash
./dv down lab --siem opensearch
./dv up lab --siem opensearch --profile tiny
```

**Out of memory** — increase Docker Desktop memory to 6 GB minimum (Docker Desktop → Settings → Resources → Memory).

---

### `vagrant` returns "A Vagrant environment or target machine is required"

You are in the wrong directory. Always `cd` into `vagrant/` first:

```bash
cd /path/to/detection-validator/vagrant
vagrant status
```

---

### Vagrant VM boots but services not active

SSH in and check:

```bash
cd vagrant
vagrant ssh
systemctl status victim-agent
journalctl -u victim-agent -n 20
exit
```

If services failed to start, re-provision:

```bash
vagrant provision
```

---

### `dv validate` shows 0 hits for all rules

Attacks ran more than 1 hour ago. Extend the window:

```bash
dv validate examples/detections/sigma/ --since 24
```

Check events are in OpenSearch:

```bash
dv siem status      # shows document count
dv siem test --size 5   # shows sample events
```

---

### `./dv up` fails with `command not found` error inside the script

Run the doctor check from the shell script to verify Docker prerequisites:

```bash
./dv doctor
```

Fix any ✗ errors it reports.

---

## Port reference

| Port | What it is | How to access |
|---|---|---|
| `9200` | OpenSearch API | `https://localhost:9200` |
| `5601` | OpenSearch Dashboards | `https://localhost:5601` |
| `8000` | Splunk mock UI | `http://localhost:8000` |
| `8088` | Splunk HEC (ingestion) | `http://localhost:8088` |
| `8888` | Vulnerable service (VM) | `http://localhost:8888/health` |
| `9098` | Victim agent — Mac → VM | `http://localhost:9098/health` |
| `9099` | Victim agent — Docker container | `http://localhost:9099/health` |

---

## Quick reference

| Task | Command |
|---|---|
| Activate Python environment | `source .venv/bin/activate` |
| Check everything works | `dv doctor` |
| Start Docker stack | `./dv up lab --siem opensearch --profile tiny` |
| Stop Docker stack | `./dv down lab --siem opensearch` |
| Start Vagrant VM | `cd vagrant && vagrant up && cd ..` |
| Stop Vagrant VM | `cd vagrant && vagrant halt && cd ..` |
| SSH into VM | `cd vagrant && vagrant ssh` |
| Run Log4Shell attack | `dv attack --cve CVE-2021-44228 --target vagrant --agent-port 9098 --watch` |
| Run PrintNightmare attack | `dv attack --cve CVE-2021-34527 --target vagrant --agent-port 9098 --watch` |
| Run ProxyLogon attack | `dv attack --cve CVE-2021-26855 --target vagrant --agent-port 9098 --watch` |
| Validate rules (last 1 hour) | `dv validate examples/detections/sigma/ --since 1` |
| Generate HTML report | `dv validate examples/detections/sigma/ --since 1 --format json \| dv report --format html -o report.html && open report.html` |
| Check SIEM status | `dv siem status` |
| Check agent status | `dv agent status` |
| View live events | Open `https://localhost:5601` → Discover → `dv-telemetry-*` |
