# detection-validator

Multi-SIEM detection validation platform. Simulate CVE-based attacks against a real Linux victim, capture auditd telemetry, validate detection rules against live SIEM data or offline event files, and generate shareable reports.

## Quick start

```bash
# Prerequisites: Docker 24+, Vagrant + vagrant-qemu, Python 3.12, uv
./dv doctor

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

## Commands

| Command | Description |
|---|---|
| `dv attack` | Simulate CVE-based exploit steps against a victim |
| `dv validate` | Query live SIEM for rule hits, report PASS/FAIL per rule |
| `dv match` | Same evaluation offline against a local JSONL event file |
| `dv report` | Render results as CLI summary / SARIF / HTML |
| `dv ingest` | Parse Sigma/Splunk/KQL/YARA/EQL rules to canonical JSONL |
| `dv map` | Map parsed rules to ATT&CK techniques |
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

## Sections

- [Architecture](architecture.md)
- [Docker images](docker-images.md)
- [Configuration](configuration.md)
- [SIEM backends](siem-backends.md)
- [Attack scenarios](scenarios.md)
- [API reference](api.md)
- [GitHub Action](github-action.md)
