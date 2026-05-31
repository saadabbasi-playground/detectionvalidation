# Implementation Plan: `dv demo` + External SIEM Integration

## Context (read this first if you're a fresh agent)

Repo: `/Users/saadabbasi/Documents/Documents/Learning/DetectionValidationV2`. It's a detection validation platform: real exploits run on a Vagrant VM, auditd captures kernel events, Vector ships to OpenSearch, `dv validate` matches Sigma rules. The CLI is `.venv/bin/detection-validator` (also `./dv` shell wrapper for stack management).

**Goals of this plan:**
1. **Reliability**: make `dv doctor` catch silent failures (auditd disabled, Vector stuck, password not substituted).
2. **One-command demo**: `dv demo --cve CVE-2021-44228` brings up everything, runs an attack, validates, prints results.
3. **External SIEM**: users register their own OpenSearch/Elastic/Splunk and `dv` ships events + runs validation against it.

**Files to read before starting any phase:**
```
./dv                                           # shell orchestrator
src/detection_validator/cli.py                 # Click CLI
src/detection_validator/validator/engine.py    # Sigma → ES query translation
vagrant/Vagrantfile
vagrant/files/vector.toml
vagrant/files/victim-agent.py
compose/shippers/vector.yml
compose/profiles/standard.env
compose/profiles/tiny.env
```

**Three silent failures discovered in past sessions (these are the bar to clear):**
1. auditd silently set `enabled 0` after log rotation — no events for 5 days, no alert.
2. victim-agent kept tailing pre-rotation `audit.log` — JSONL froze, no signal.
3. Splunk sink retry loop deadlocked Vector → OpenSearch, despite `when_full: drop_newest`.

---

## Phase 1 — Reliability (do first, blocks everything else)

### Task 1.1: End-to-end canary in `dv doctor`

**Why**: today's `dv doctor` checks env but not whether telemetry actually flows end-to-end.

**Step 1** — read the current `doctor` command:
```bash
grep -n "def cmd_doctor\|@cli.command.*doctor\|'doctor'" src/detection_validator/cli.py
```
Then read the function body (next ~80 lines).

**Step 2** — add a `--canary` flag that does:
1. POST a synthetic event to victim-agent: `POST http://localhost:9098/simulate` with payload
   `{"key":"dv_canary","comm":"dv_canary","exe":"/usr/bin/dv_canary","uid":"0","technique":"DV_TEST","cmd_output":"<uuid>"}`
2. Poll OpenSearch every 1s for up to 15s: `GET https://localhost:9200/dv-telemetry-*/_search` with query `{"query":{"match":{"cmd_output":"<uuid>"}}}`
3. Print PASS if found, otherwise FAIL with hints about which stage is broken.

**Step 3** — auto-diagnose calls when canary fails (read-only, prints actionable errors):
```bash
ssh -p 50022 ... vagrant@127.0.0.1 "sudo auditctl -s | grep enabled"
ssh -p 50022 ... vagrant@127.0.0.1 "sudo systemctl is-active victim-agent vector"
ssh -p 50022 ... vagrant@127.0.0.1 "sudo journalctl -u vector --since '5 minutes ago' | grep -iE 'error|stuck'"
```

**Verification:**
```bash
.venv/bin/detection-validator doctor --canary
# Expect: "✓ Canary event roundtrip: 2.3s" or specific failure stage
```

### Task 1.2: Auto-recovery command (`dv repair`)

**Why**: re-running fixes manually is tedious. Provide one command that resets the pipeline to known-good state without `vagrant reload`.

**Step 1** — add `dv repair` Click command in `cli.py` that SSH's in and runs:
```bash
sudo auditctl -e 1
sudo systemctl restart victim-agent
sudo systemctl restart vector
```

**Step 2** — verify after repair:
```bash
.venv/bin/detection-validator doctor --canary
```

### Task 1.3: Vector config sanity at provision time

**Why**: today the password substitution silently failed because Vector loads `vector.toml` but provision substituted only `vector.yaml`.

**Step 1** — edit `vagrant/Vagrantfile`, in the inline shell after vector config is installed (~line 60), add:
```bash
# Fail fast if password substitution didn't happen
if grep -q 'password = "change-me"' /etc/vector/vector.toml; then
  echo "FATAL: password substitution failed in vector.toml" >&2
  exit 1
fi
```

**Verification**: re-running `vagrant provision` must still succeed.

---

## Phase 2 — Single-command demo

### Task 2.1: Create `dv demo` Click command

**File to edit**: `src/detection_validator/cli.py`

**Step 1** — find where `attack` and `validate` are registered. Add a new command `demo`:
```python
@cli.command()
@click.option("--cve", default="CVE-2021-44228")
@click.option("--rules", default="examples/detections/sigma/")
@click.option("--profile", default="tiny")
def demo(cve, rules, profile):
    """One-shot demo: bring up stack, run exploit, validate rules."""
```

**Step 2** — function body orchestrates these subprocess calls in order, with progress prints, failing loudly:

```python
import subprocess, sys, time, pathlib, socket

REPO = pathlib.Path(__file__).resolve().parents[3]
VAGRANT_DIR = REPO / "vagrant"

def run(cmd, cwd=None, check=True):
    click.echo(f"$ {' '.join(cmd)}")
    return subprocess.run(cmd, cwd=cwd, check=check)

# Step 1: Docker stack
click.echo("▶  Bringing up Docker stack...")
run(["./dv", "up", "-d", profile], cwd=REPO)

# Step 2: Vagrant VM
click.echo("▶  Ensuring Vagrant VM is running...")
status = subprocess.run(["vagrant", "status", "--machine-readable"],
                        cwd=VAGRANT_DIR, capture_output=True, text=True).stdout
if "state,running" not in status:
    run(["vagrant", "up"], cwd=VAGRANT_DIR)

# Step 3: SSH tunnel for vuln service if 8888 is taken on host
def port_taken(p):
    s = socket.socket()
    try: s.connect(("127.0.0.1", p)); return True
    except: return False
    finally: s.close()
vuln_port = 8888 if not port_taken(8888) else 9088
if vuln_port == 9088 and not port_taken(9088):
    subprocess.Popen(["ssh", "-f", "-N", "-L", "9088:localhost:8888",
                      "-p", "50022", "-i", str(VAGRANT_DIR / ".vagrant/machines/default/qemu/private_key"),
                      "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
                      "vagrant@127.0.0.1"])
    time.sleep(2)

# Step 4: Canary
click.echo("▶  Running canary...")
result = subprocess.run([sys.argv[0], "doctor", "--canary"], capture_output=True, text=True)
if "FAIL" in result.stdout:
    click.echo("Canary failed, attempting auto-repair...")
    run([sys.argv[0], "repair"])
    run([sys.argv[0], "doctor", "--canary"])

# Step 5: Attack
click.echo(f"▶  Running attack {cve}...")
run([sys.argv[0], "attack", "--cve", cve, "--target", "vagrant",
     "--agent-port", "9098", "--mode", "exploit",
     "--vuln-port", str(vuln_port)])

# Step 6: Wait for Vector flush
click.echo("▶  Waiting 5s for Vector flush...")
time.sleep(5)

# Step 7: Validate
click.echo("▶  Validating rules...")
run([sys.argv[0], "validate", rules, "--since", "0.1"])

click.echo("\n✓ Demo complete. View events at http://localhost:5601")
```

**Verification:**
```bash
.venv/bin/detection-validator demo
# Expect: stack comes up, attack runs, 4+ rules PASS
```

### Task 2.2: Make `tiny` profile actually boot fast

Read `compose/profiles/tiny.env`. Add if missing:
```
OPENSEARCH_HEAP=1g
OPENSEARCH_JAVA_OPTS=-Xms512m -Xmx512m
DASHBOARDS_MEMORY=512m
DV_ENABLE_SPLUNK=false
DV_ENABLE_DASHBOARDS=false
```

If `DV_ENABLE_DASHBOARDS` isn't wired in `compose/docker-compose.yml`, gate the dashboards service on it:
```yaml
opensearch-dashboards:
  profiles: ["${DV_ENABLE_DASHBOARDS:-true}"]
```
Then `./dv up tiny` skips dashboards → demo boots in ~30s instead of 2min.

---

## Phase 3 — External SIEM integration

### Task 3.1: SIEM connection registry

**Goal**: users register their own SIEM once, then `dv validate --siem my-prod` and `dv attack ... --emit-to my-prod` use it.

**Step 1** — create config schema at `~/.detectionvalidator/siems.yaml`:
```yaml
siems:
  - name: local
    type: opensearch
    url: https://localhost:9200
    username: admin
    password: DetectVal123!
    verify_tls: false
  - name: my-prod
    type: elasticsearch
    url: https://elastic.example.com:9200
    api_key: ${ELASTIC_API_KEY}
    verify_tls: true
```

**Step 2** — check if `dv siem` exists:
```bash
grep -n "def siem\|@cli.group.*siem" src/detection_validator/cli.py
```
If it exists, extend it. If not, create:
```python
@cli.group()
def siem(): ...

@siem.command("add")
@click.argument("name")
@click.option("--type", required=True, type=click.Choice(["opensearch","elasticsearch","splunk"]))
@click.option("--url", required=True)
@click.option("--username")
@click.option("--password")
@click.option("--api-key")
@click.option("--token")
def siem_add(...): # write to ~/.detectionvalidator/siems.yaml

@siem.command("list")
def siem_list(): # pretty-print configured SIEMs

@siem.command("test")
@click.argument("name")
def siem_test(name): # call _cluster/health (ES/OS) or /services/server/info (Splunk)
```

**Step 3** — in `validator/engine.py`, find where the OpenSearch client is constructed (hardcoded today). Replace with:
```python
def load_siem(name="local") -> dict:
    cfg = yaml.safe_load((pathlib.Path.home() / ".detectionvalidator/siems.yaml").read_text())
    for s in cfg["siems"]:
        if s["name"] == name: return s
    raise ValueError(f"No SIEM named {name}")
```

**Verification:**
```bash
.venv/bin/detection-validator siem add prod --type opensearch --url https://x.example.com --username u --password p
.venv/bin/detection-validator siem test prod
# Expect: "✓ prod: cluster_status=green nodes=3" or specific connection error
```

### Task 3.2: Multi-output Vector (ship events to external SIEMs)

**Goal**: when user registers `my-prod`, Vector also ships there.

**Step 1** — add Click command `dv siem attach <name>` that:
1. Reads the SIEM config
2. SSH's into the VM
3. Appends a new sink block to `/etc/vector/vector.toml`
4. Runs `sudo vector validate /etc/vector/vector.toml`
5. Runs `sudo systemctl restart vector`

```python
@siem.command("attach")
@click.argument("name")
def siem_attach(name):
    s = load_siem(name)
    if s["type"] in ("opensearch", "elasticsearch"):
        block = f"""
[sinks.{name}_out]
type = "elasticsearch"
inputs = ["parse_events"]
endpoints = ["{s['url']}"]
api_version = "v8"
[sinks.{name}_out.auth]
strategy = "basic"
user = "{s['username']}"
password = "{s['password']}"
[sinks.{name}_out.bulk]
index = "dv-telemetry-%Y.%m.%d"
[sinks.{name}_out.tls]
verify_certificate = {str(s.get('verify_tls', True)).lower()}
[sinks.{name}_out.buffer]
type = "memory"
max_events = 1000
when_full = "drop_newest"
"""
    elif s["type"] == "splunk":
        # similar with splunk_hec_logs
        ...
    # SSH and append
    subprocess.run(["ssh", ..., f"echo '{block}' | sudo tee -a /etc/vector/vector.toml && sudo systemctl restart vector"])
```

**Critical**: every sink must have `buffer.when_full = "drop_newest"` so a misconfigured external SIEM doesn't deadlock the local one (today's bug).

**Verification:**
```bash
.venv/bin/detection-validator siem add prod --type opensearch --url https://localhost:9200 --username admin --password DetectVal123!
.venv/bin/detection-validator siem attach prod
.venv/bin/detection-validator attack --cve CVE-2021-44228 --target vagrant ...
# Check events landed in BOTH local and prod indices
```

### Task 3.3: `dv validate --siem` honors the registry

**Step 1** — read current implementation:
```bash
grep -n "siem" src/detection_validator/cli.py | grep -i validate
```

**Step 2** — confirm `--siem prod` looks up the registry (not just hardcoded credentials). If not, refactor to use `load_siem(name)`.

**Verification:**
```bash
.venv/bin/detection-validator validate examples/detections/sigma/ --siem prod --since 1
```

---

## Phase 4 — Optional: installable distribution

Only do this once Phase 1–3 verify clean.

**Step 1** — check for `pyproject.toml` console_scripts:
```bash
grep -n "entry_points\|console_scripts" pyproject.toml setup.py 2>/dev/null
```

**Step 2** — write `install.sh` at repo root:
```bash
#!/usr/bin/env bash
set -e
command -v docker >/dev/null || { echo "Install Docker"; exit 1; }
command -v vagrant >/dev/null || { echo "Install Vagrant + vagrant-qemu plugin"; exit 1; }
git clone https://github.com/saadabbasi-playground/detectionvalidation.git
cd detectionvalidation
python3 -m venv .venv
.venv/bin/pip install -e .
echo 'export PATH=$PWD/.venv/bin:$PATH' >> ~/.zshrc
echo "Run: detection-validator demo"
```

---

## Exit criteria (define DONE)

A successful run of:
```bash
detection-validator demo
```
on a cold machine (no containers up, VM halted) must:
1. Bring up the stack, VM, network.
2. Auto-recover from any of the 3 silent failures.
3. Run the exploit.
4. Print `4+ PASS` for Log4Shell rules within 4 minutes total.
5. Exit 0.

And:
```bash
detection-validator siem add x --type opensearch --url ... --username ... --password ...
detection-validator siem test x
detection-validator siem attach x
detection-validator attack --cve CVE-2021-44228 --target vagrant ...
detection-validator validate examples/detections/sigma/ --siem x --since 1
```
must succeed end-to-end with events visible in `x`.

---

## Hand-off rules

Tackle phases in order. **After each task**:
1. Run the verification command exactly as written.
2. If it fails, paste the output and stop — don't guess fixes that span multiple files.
3. Commit per task with message format `phase-N.M: <one-line task summary>`.
4. Don't add features not in this plan. Scope creep here means demo regressions.
