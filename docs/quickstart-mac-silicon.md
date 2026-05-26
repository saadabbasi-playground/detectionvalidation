# Quickstart — Mac Apple Silicon (M1 / M2 / M3 / M4)

This guide walks you through running detection-validator from scratch on a Mac with an Apple Silicon chip. Every command is written out exactly as you should type it. Nothing is assumed.

---

## What you will end up with

By the end of this guide you will have:

- OpenSearch running in Docker (your SIEM — stores attack telemetry)
- A Ubuntu 22.04 ARM64 virtual machine (the victim — generates real Linux audit events)
- The `dv` Python CLI installed and working
- A successful attack simulation against the VM
- A validation report showing which detection rules fired

---

## Part 1 — Install prerequisites

Open **Terminal** on your Mac and run each block in order.

### 1.1 Install Homebrew (if not already installed)

```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

After it finishes, follow any instructions it prints about adding Homebrew to your PATH. Then close and reopen Terminal.

Verify:

```bash
brew --version
```

You should see a version number like `Homebrew 4.x.x`.

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

Download and install Docker Desktop for Mac (Apple Silicon):
**https://www.docker.com/products/docker-desktop/**

Make sure you download the **Apple Silicon** version (not Intel).

After installing, open Docker Desktop from your Applications folder and wait for the whale icon in your menu bar to stop animating. That means the Docker daemon is running.

Give Docker Desktop more memory — it needs at least 6 GB:

1. Open Docker Desktop
2. Click the gear icon (Settings) in the top right
3. Click **Resources** → **Memory**
4. Drag the slider to at least **6 GB**
5. Click **Apply & Restart**

Verify Docker is running:

```bash
docker --version
docker ps
```

`docker ps` should return an empty table (no error).

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

### 1.6 Install the vagrant-qemu plugin

This plugin lets Vagrant use QEMU with Apple's native Hypervisor Framework — no emulation, full ARM64 speed.

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

All commands from here on must be run from inside the `detection-validator/` directory unless told otherwise.

---

### 2.2 Create the Python virtual environment

```bash
uv venv
```

This creates a `.venv/` folder inside the project.

---

### 2.3 Install the Python package

```bash
uv pip install -e ".[dev]"
```

This installs the `dv` CLI tool and all dependencies. It takes about 30–60 seconds.

---

### 2.4 Activate the virtual environment

```bash
source .venv/bin/activate
```

Your terminal prompt will change to show `(detection-validator)` at the start. This means the virtual environment is active and `dv` is available.

> **Important:** you must run `source .venv/bin/activate` every time you open a new Terminal window before using `dv`. If you ever see `dv: command not found`, this is why.

Verify the CLI is working:

```bash
dv --help
```

You should see a list of available commands.

---

### 2.5 Save the OpenSearch password permanently

The lab stack uses `DetectVal123!` as the OpenSearch admin password. Add it to your shell profile so you never have to type it again:

```bash
echo 'export OPENSEARCH_INITIAL_ADMIN_PASSWORD="DetectVal123!"' >> ~/.zshrc
source ~/.zshrc
```

Verify:

```bash
echo $OPENSEARCH_INITIAL_ADMIN_PASSWORD
```

Expected: `DetectVal123!`

---

## Part 3 — Run the pre-flight check

```bash
dv doctor
```

This checks everything before you waste time debugging. Run it now, before starting any containers.

At this point you will likely see some warnings because the Docker stack and Vagrant VM are not running yet. That is fine. The output should look like this:

```
dv doctor — environment pre-flight check

  ✓ Python 3.12.5
  ✓ uv 0.11.13
  ✓ Docker 28.3.2
  ✓ Docker daemon running
  ✓ Docker network detectval-lab    ← may show ✗ until you start Docker stack
  ✓ Vagrant 2.4.9
  ✓ Vagrant plugin vagrant-qemu
  ⚠ Vagrant VM not running          ← expected at this stage
  ✓ OPENSEARCH_INITIAL_ADMIN_PASSWORD set
  ⚠ OpenSearch not reachable        ← expected at this stage
  ...
```

Fix any ✗ (red) errors before continuing. ⚠ (yellow) warnings are fine for now.

If you see `✗ Docker network detectval-lab` — create it:

```bash
docker network create detectval-lab
```

---

## Part 4 — Start the Docker stack

The Docker stack runs the SIEM (OpenSearch), a Splunk mock receiver, the log shipper (Vector), and a Linux victim container.

```bash
./dv up lab --siem opensearch --profile tiny
```

> `--profile tiny` limits memory usage to ~600 MB per service. Recommended for 16 GB MacBooks. Use `--profile standard` if you have 32 GB.

This command builds the Docker images on first run, which takes 3–5 minutes. Subsequent starts take about 30 seconds.

Wait until you see `[dv] Stack 'lab' is running.` in the output, then check:

```bash
docker ps --format "table {{.Names}}\t{{.Status}}"
```

Expected — every container must say `(healthy)`:

```
NAMES                          STATUS
dv-linux-victim                Up 2 minutes (healthy)
dv-vector                      Up 2 minutes (healthy)
dv-opensearch                  Up 2 minutes (healthy)
dv-opensearch-dashboards       Up 2 minutes (healthy)
detectval-splunk               Up 2 minutes (healthy)
```

If any container says `(starting)`, wait 30 more seconds and run `docker ps` again. OpenSearch can take up to 60 seconds to become healthy.

Confirm OpenSearch is accepting connections:

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

## Part 5 — Start the Vagrant VM

The Vagrant VM runs a real Ubuntu 22.04 ARM64 kernel with `auditd`. This is what produces genuine Linux syscall telemetry. The Docker victim container produces synthetic events — the Vagrant VM produces the real thing.

You must `cd` into the `vagrant/` directory first. `vagrant` commands only work where the `Vagrantfile` lives.

```bash
cd vagrant
vagrant up
```

**First run:** downloads the Ubuntu ARM64 box (~500 MB) and provisions the VM. Takes about 5 minutes. You will see a lot of output — that is normal.

**Subsequent runs:** takes about 30 seconds.

When it finishes, check that the three services inside the VM are running:

```bash
vagrant ssh -c "systemctl is-active victim-agent vector auditd"
```

Expected — three lines each saying `active`:

```
active
active
active
```

Check that the victim agent is reachable from your Mac:

```bash
vagrant ssh -c "curl -s http://localhost:9099/health"
```

Expected:

```json
{"status": "ok", "host": "dv-victim", "mode": "vm"}
```

Also verify the host-side port forwarding works (host port 9098 → VM port 9099):

```bash
curl http://localhost:9098/health
```

Expected — same JSON response as above.

Go back to the project root:

```bash
cd ..
```

---

## Part 6 — Run the pre-flight check again

Now that everything is running, re-run `dv doctor` from the project root:

```bash
dv doctor
```

Expected — everything green:

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
  ⚠ KEV cache empty  ← fix this below
```

Fix the KEV cache warning (downloads CVE threat intel — takes ~10 seconds):

```bash
dv intel update --source attack
dv intel update --source cve
```

Run `dv doctor` one more time to confirm everything is green.

---

## Part 7 — Simulate attacks

Now simulate three real CVE exploits against the Vagrant VM. Each command executes attack steps on the VM, then waits for Vector to ship the resulting audit events to OpenSearch.

### Log4Shell (CVE-2021-44228) — CVSS 10.0

Remote code execution via the Java Log4j logging library. Used in hundreds of thousands of real attacks in late 2021.

```bash
dv attack --cve CVE-2021-44228 --target vagrant --agent-port 9098 --watch
```

Expected output:

```
⚔  Running attack scenario  cve=CVE-2021-44228  target=vagrant

Scenario: Log4Shell Remote Code Execution
  CVE: CVE-2021-44228  CVSS: 10.0

  ✓ T1190     key=network_connect  rc=0
  ✓ T1059.004 key=shell_exec       rc=0
    uid=0(root) gid=0(root) groups=0(root)

✓ 2 steps executed.

Attack events in OpenSearch (last 20):
  T1190         network_connect   exe=/usr/bin/curl   uid=33
  T1059.004     shell_exec        exe=/bin/bash       uid=33
    uid=0(root) gid=0(root) groups=0(root) ...
```

---

### PrintNightmare (CVE-2021-34527) — CVSS 8.8

Windows Print Spooler privilege escalation. Simulated on Linux as privilege escalation + persistence steps.

```bash
dv attack --cve CVE-2021-34527 --target vagrant --agent-port 9098 --watch
```

Expected output:

```
⚔  Running attack scenario  cve=CVE-2021-34527  target=vagrant

Scenario: PrintNightmare Spooler Service Exploitation
  CVE: CVE-2021-34527  CVSS: 8.8

  ✓ T1068     key=priv_change  rc=0
  ✓ T1547.012 key=file_write   rc=0
  ✓ T1574.001 key=file_write   rc=0

✓ 3 steps executed.
```

---

### ProxyLogon (CVE-2021-26855) — CVSS 9.1

Microsoft Exchange Server SSRF leading to remote code execution. Simulated as SSRF + webshell + credential access.

```bash
dv attack --cve CVE-2021-26855 --target vagrant --agent-port 9098 --watch
```

Expected output:

```
⚔  Running attack scenario  cve=CVE-2021-26855  target=vagrant

Scenario: ProxyLogon Exchange Server SSRF Exploitation
  CVE: CVE-2021-26855  CVSS: 9.1

  ✓ T1190     key=network_connect  rc=0
  ✓ T1505.003 key=file_write       rc=0
  ✓ T1078     key=identity_check   rc=0
  ✓ T1552.001 key=sensitive_file   rc=0

✓ 4 steps executed.
```

---

## Part 8 — Validate detections

Now check whether your detection rules fired against the telemetry the attacks generated.

```bash
dv validate examples/detections/sigma/ --since 1
```

This loads every Sigma rule in `examples/detections/sigma/`, queries OpenSearch for matching events from the last hour, and reports PASS or FAIL per rule:

```
 Rule                            Techniques              Hits  SIEM         Status
 LSASS Memory Dump via TM        T1003.001                  0  opensearch   ✗ FAIL
 Log4Shell JNDI Injection        T1190, T1059.004           6  opensearch   ✓ PASS
 MSHTA Spawning Windows Shell    T1218.005, T1059.001       0  opensearch   ✗ FAIL
 Nmap Port Scan Detected         T1046                      0  opensearch   ✗ FAIL
 PrintNightmare Spooler Abuse    T1068, T1547.012           4  opensearch   ✓ PASS
 ProxyLogon Exchange SSRF        T1190, T1505.003           5  opensearch   ✓ PASS
 Test                            T1499, T1059.004           3  opensearch   ✓ PASS

Results: 7 rule(s)  4 PASS  3 FAIL  0 ERROR  0 SKIP  (1.3s)
```

> **Why do LSASS, MSHTA, and Nmap fail?**
> Those rules detect Windows-specific processes (lsass.exe, mshta.exe) or require an active port scan to be running. The Vagrant VM is Linux — those events are never generated. The rules themselves are correct. This is expected behaviour.

If `--since 1` shows 0 hits for everything, your attacks ran more than 1 hour ago. Extend the window:

```bash
dv validate examples/detections/sigma/ --since 24
```

---

## Part 9 — Generate a report

### CLI report (terminal output)

```bash
dv validate examples/detections/sigma/ --since 1 --format json | dv report
```

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
│ Generated:   2026-05-26 04:55 UTC │
╰───────────────────────────────────╯

ATT&CK Tactic Coverage
  Tactic                   Coverage      Techniques covered
  Credential Access        0/1 (0%)      —
  Defense Evasion          1/2 (50%)     T1078
  Execution                1/2 (50%)     T1059.004
  Impact                   1/1 (100%)    T1499
  Initial Access           1/1 (100%)    T1190
  Persistence              2/2 (100%)    T1505.003, T1547.012
  Privilege Escalation     2/2 (100%)    T1068, T1574.001
```

### HTML report (open in browser)

```bash
dv validate examples/detections/sigma/ --since 1 --format json | dv report --format html -o report.html
open report.html
```

### SARIF report (for GitHub Code Scanning)

```bash
dv validate examples/detections/sigma/ --since 1 --format json | dv report --format sarif -o scan.sarif
```

> **How the pipe works:** `dv validate` sends its progress messages to the terminal (stderr) and the JSON results to the pipe (stdout). `dv report` reads the JSON from the pipe. You do not need any extra flags — it just works.

---

## Part 10 — View live telemetry

### OpenSearch Dashboards (browser UI)

Open this URL in your browser:

```
https://localhost:5601
```

Your browser will warn about an invalid certificate — click **Advanced** → **Proceed** (the certificate is self-signed for local use).

Log in with:
- **Username:** `admin`
- **Password:** `DetectVal123!`

Then:
1. Click the hamburger menu (top left)
2. Click **Discover**
3. If prompted, create an index pattern: type `dv-telemetry-*` and click **Create index pattern**
4. Set the time range in the top right to **Last 1 hour** (or longer if needed)

You will see all the audit events the attacks generated. Each event has fields like `technique`, `exe`, `uid`, `key`, `cmd_output`.

Useful search queries to type in the search bar:

| Query | What it shows |
|---|---|
| `technique: T1190` | Exploitation / network callback events |
| `technique: T1068` | Privilege escalation events |
| `technique: T1059.004` | Shell execution events |
| `exe: /usr/bin/curl` | All curl invocations |
| `key: shell_exec` | All shell execution audit records |

### OpenSearch API (command line)

```bash
# Count all events
curl -sk -u "admin:DetectVal123!" "https://localhost:9200/dv-telemetry-*/_count" | python3 -m json.tool

# Show 5 most recent events
curl -sk -u "admin:DetectVal123!" \
  "https://localhost:9200/dv-telemetry-*/_search?size=5&sort=timestamp:desc&pretty"

# Show only events that have a technique tag
curl -sk -u "admin:DetectVal123!" \
  "https://localhost:9200/dv-telemetry-*/_search?pretty" \
  -H "Content-Type: application/json" \
  -d '{"query": {"exists": {"field": "technique"}}, "size": 10}'
```

### Inside the VM

```bash
cd vagrant
vagrant ssh
```

You are now inside the Ubuntu VM. Run:

```bash
# Watch audit events arrive in real time (Ctrl+C to stop)
sudo tail -f /var/log/audit/audit-events.jsonl

# See all events from the last attack session
sudo cat /var/log/audit/audit-events.jsonl | python3 -m json.tool | less

# Check the victim agent is running
systemctl status victim-agent

# Check vector is shipping events
systemctl status vector

# Exit the VM
exit
```

---

## Part 11 — Stop everything

When you are done:

```bash
# Stop the Vagrant VM (saves state, can be resumed)
cd vagrant && vagrant halt && cd ..

# Stop the Docker stack
./dv down lab --siem opensearch

# Or stop and delete all Docker volumes (full clean)
./dv down lab --siem opensearch --volumes
```

To start again next time, just repeat Parts 4 and 5 (start Docker, start Vagrant VM).

---

## Daily workflow (after first setup)

Once everything is installed, your day-to-day flow is:

```bash
# Open Terminal, navigate to project, activate venv
cd detection-validator
source .venv/bin/activate

# Start Docker stack
./dv up lab --siem opensearch --profile tiny

# Start Vagrant VM (from vagrant/ directory)
cd vagrant && vagrant up && cd ..

# Check everything is healthy
dv doctor

# Run attacks
dv attack --cve CVE-2021-44228 --target vagrant --agent-port 9098 --watch

# Validate rules
dv validate examples/detections/sigma/ --since 1 --format json | dv report

# Open HTML report
dv validate examples/detections/sigma/ --since 1 --format json | dv report --format html -o report.html && open report.html
```

---

## Troubleshooting

### `dv: command not found`

The virtual environment is not active. Fix:

```bash
source .venv/bin/activate
```

---

### `dv doctor` shows `✗ Docker network detectval-lab`

Create the network manually:

```bash
docker network create detectval-lab
```

---

### `dv doctor` shows `⚠ OpenSearch reachable but auth failed`

The password environment variable is not set or is wrong. Fix:

```bash
export OPENSEARCH_INITIAL_ADMIN_PASSWORD="DetectVal123!"
dv doctor
```

To make it permanent (so you never need to type it again):

```bash
echo 'export OPENSEARCH_INITIAL_ADMIN_PASSWORD="DetectVal123!"' >> ~/.zshrc
source ~/.zshrc
```

---

### OpenSearch container keeps restarting — `vm.max_map_count too low`

```bash
docker run --rm --privileged alpine sysctl -w vm.max_map_count=262144
./dv up lab --siem opensearch --profile tiny
```

---

### Docker containers are out of memory / crash-looping

Docker Desktop does not have enough memory. Fix:

1. Open Docker Desktop
2. Settings → Resources → Memory
3. Set to at least **6 GB**
4. Click **Apply & Restart**
5. Then restart the stack: `./dv down lab --siem opensearch && ./dv up lab --siem opensearch --profile tiny`

---

### `vagrant up` fails with a QEMU / HVF error

The Hypervisor Framework needs permissions. Fix:

1. Open **System Settings** → **Privacy & Security**
2. Scroll down to find a block about Vagrant or QEMU — click **Allow**
3. Try again: `vagrant destroy -f && vagrant up`

Also make sure the plugin is up to date:

```bash
vagrant plugin update vagrant-qemu
```

---

### `vagrant` commands return "A Vagrant environment or target machine is required"

You ran `vagrant` from the wrong directory. Always `cd vagrant` first:

```bash
cd /path/to/detection-validator/vagrant
vagrant status
vagrant ssh
vagrant up
```

---

### `dv validate` shows 0 hits for all rules

The attacks ran more than 1 hour ago. Use a wider window:

```bash
dv validate examples/detections/sigma/ --since 24
```

Also confirm events are in OpenSearch:

```bash
dv siem status       # check document count
dv siem test --size 5    # show sample events
```

---

### Vagrant VM boots but victim-agent or vector is not active

SSH into the VM and check:

```bash
cd vagrant && vagrant ssh
systemctl status victim-agent
systemctl status vector
journalctl -u victim-agent -n 30
```

If they are not running, re-provision:

```bash
exit
vagrant provision
```

---

## Port reference

| Port | Service | URL |
|---|---|---|
| `9200` | OpenSearch API | `https://localhost:9200` |
| `5601` | OpenSearch Dashboards | `https://localhost:5601` |
| `8000` | Splunk mock UI | `http://localhost:8000` |
| `8088` | Splunk HEC (log ingestion) | `http://localhost:8088` |
| `9098` | Victim agent (Mac→VM) | `http://localhost:9098/health` |
| `9099` | Victim agent (Docker container) | `http://localhost:9099/health` |

---

## What each tool does

| Tool | Command | Purpose |
|---|---|---|
| `./dv` (shell script) | `./dv up`, `./dv down`, `./dv status` | Start/stop Docker containers |
| `dv` (Python CLI) | `dv doctor`, `dv attack`, `dv validate`, etc. | Everything else |
| Docker Desktop | (GUI) | Runs all containers |
| Vagrant + QEMU | `vagrant up/halt/ssh` | Manages the Ubuntu VM |
| OpenSearch | (container) | Stores and searches audit events |
| Vector | (container) | Ships audit events from VM to OpenSearch |
| victim-agent | (runs in VM) | Executes attack steps, writes audit events |
| auditd | (runs in VM) | Linux kernel audit daemon — records syscalls |
