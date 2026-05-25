# detection-validator

Multi-SIEM detection validation platform. Simulate CVE-based attacks against a real Linux victim, capture auditd telemetry, validate detection rules against live SIEM data or offline event files, and generate shareable reports.

## Quick start

```bash
# Prerequisites: Docker 24+, Vagrant + vagrant-qemu, Python 3.12, uv
# Check your environment first — fixes problems before they waste time
dv doctor

# Start SIEM stack
export OPENSEARCH_INITIAL_ADMIN_PASSWORD="<your-password>"
./dv up lab --siem opensearch --profile tiny

# Start Vagrant VM (real auditd telemetry)
cd vagrant && vagrant up && cd ..

# Simulate attack, validate live, generate report
dv attack --cve CVE-2021-44228 --target vagrant --agent-port 9098 --watch
dv validate examples/detections/sigma/ --since 1 --format json | dv report
dv validate examples/detections/sigma/ --since 1 --format json | dv report --format html -o report.html

# Or match offline — no SIEM required
vagrant ssh -c "sudo cat /var/log/audit/audit-events.jsonl" > events.jsonl
dv match --events events.jsonl examples/detections/sigma/ --since 0 --format json | dv report
```

## dv doctor

Run `dv doctor` before your first use, or any time something isn't working.
It checks 13 things and exits non-zero if any are broken:

| Check | What it tests |
|---|---|
| Python, uv | version requirements |
| Docker | installed, daemon running, `detectval-lab` network present |
| Vagrant | installed, `vagrant-qemu` plugin, VM running |
| OpenSearch | reachable at `https://localhost:9200` |
| Splunk mock | reachable at `http://localhost:8000` |
| `OPENSEARCH_INITIAL_ADMIN_PASSWORD` | env var set |
| Victim agent | responds at `localhost:9098` or `9099` |
| ATT&CK KB | local cache populated |
| KEV cache | NVD/KEV data downloaded |

```bash
dv doctor          # show status of all checks
dv doctor --fix    # also auto-download empty intelligence caches
```

## Commands

| Command | Description |
|---|---|
| `dv doctor` | Pre-flight check: tools, containers, victim agent, intelligence caches |
| `dv attack` | Simulate CVE-based exploit steps against a victim |
| `dv validate` | Query live SIEM for rule hits, report PASS/FAIL per rule |
| `dv match` | Same evaluation offline against a local JSONL event file |
| `dv report` | Render results as CLI summary / SARIF / HTML |
| `dv ingest` | Parse Sigma/Splunk/KQL/YARA/EQL rules to canonical JSONL |
| `dv map` | Map parsed rules to ATT&CK techniques |
| `dv enrich` | Fill technique names, CVE metadata, and severity from ATT&CK/NVD caches |
| `dv cve-coverage` | Analyze detection coverage gaps per CVE |
| `dv navigator` | Export ATT&CK Navigator layer from detection corpus |
| `dv intel update` | Refresh local ATT&CK, CVE, EPSS, KEV caches |

## validate vs match

| | `dv validate` | `dv match` |
|---|---|---|
| Event source | Live SIEM query | Local JSONL file |
| Requires SIEMs running | Yes | No |
| Tests full ingestion pipeline | Yes | No |
| Speed | ~1–2 s (network) | < 0.1 s (in-memory) |
| Works in offline CI | No | Yes |

Both commands produce identical output and pipe into `dv report`.

## Report formats

`dv report` reads JSON from `dv validate --format json` or `dv match --format json`:

| Format | Use case |
|---|---|
| `cli` | Terminal summary with tactic coverage breakdown |
| `json` | Pretty-printed results for scripting |
| `sarif` | GitHub Code Scanning (failing rules become PR annotations) |
| `html` | Self-contained dark-theme HTML page |

```bash
dv validate detections/ --format json | dv report                           # CLI
dv match --events events.jsonl detections/ --format json | dv report        # same, offline
dv validate detections/ --format json | dv report --format html -o r.html   # HTML
dv validate detections/ --format json | dv report --format sarif -o s.sarif # SARIF
```

## Detection pipeline

The offline analysis pipeline processes detection rules in stages:

```
dv ingest detections/   →  canonical.jsonl   (parse rules into a unified schema)
dv map -i canonical.jsonl   →  mapped.jsonl  (validate/infer ATT&CK technique IDs)
dv enrich -i mapped.jsonl   →  enriched.jsonl (fill names, CVE metadata, severity)
dv navigator -d enriched.jsonl → layer.json  (ATT&CK Navigator coverage layer)
```

### dv enrich

`dv enrich` runs three independent passes over a CanonicalDetection JSONL file:

| Pass | What it fills |
|---|---|
| `attack` | technique `.name`, `.url`, `.tactic` from local ATT&CK knowledge base |
| `cve` | create `CVEReference` entries from `cve.YYYY.NNNNN` tags; fill `.cvss_score` / `.description` from NVD/KEV/EPSS |
| `severity` | derive `.severity` from the highest CVSS score (only when still at default `MED`) |

```bash
# Full pipeline
dv ingest detections/ | dv map -i - | dv enrich > enriched.jsonl

# Skip the ATT&CK pass (CVE and severity only)
dv enrich -i mapped.jsonl --sources cve,severity -o enriched.jsonl

# Populate technique names only
dv enrich -i mapped.jsonl --sources attack -o enriched.jsonl
```

The ATT&CK and CVE knowledge bases must be populated first:

```bash
dv intel update --source attack
dv intel update --source cve --cve CVE-2021-44228,CVE-2021-34527,CVE-2021-26855
```

## Sections

- [Architecture](architecture.md)
- [Docker images](docker-images.md)
- [Configuration](configuration.md)
- [SIEM backends](siem-backends.md)
- [Attack scenarios](scenarios.md)
- [API reference](api.md)
- [GitHub Action](github-action.md)
