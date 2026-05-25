# detection-validator

Multi-SIEM detection validation platform. Simulate CVE-based attacks against a real Linux victim, capture auditd telemetry, and validate detection rules against live SIEM data.

## Quick start

```bash
# Prerequisites: Docker 24+, Vagrant + vagrant-qemu, Python 3.12, uv
./dv doctor

# Start SIEM stack
export OPENSEARCH_INITIAL_ADMIN_PASSWORD="<your-password>"
./dv up lab --siem opensearch --profile tiny

# Start Vagrant VM (real auditd telemetry)
cd vagrant && vagrant up && cd ..

# Simulate an attack and validate detections
dv attack --cve CVE-2021-44228 --target vagrant --agent-port 9098 --watch
dv validate examples/detections/sigma/ --since 1
```

## Commands

| Command | Description |
|---|---|
| `dv attack` | Simulate CVE-based exploit steps against a victim |
| `dv validate` | Query SIEM for rule hits, report PASS/FAIL per rule |
| `dv ingest` | Parse Sigma/Splunk/KQL/YARA/EQL rules to canonical JSONL |
| `dv map` | Map parsed rules to ATT&CK techniques |
| `dv cve-coverage` | Analyze detection coverage gaps per CVE |
| `dv navigator` | Export ATT&CK Navigator layer from detection corpus |
| `dv intel update` | Refresh local ATT&CK, CVE, EPSS, KEV caches |

## Sections

- [Architecture](architecture.md)
- [Docker images](docker-images.md)
- [Configuration](configuration.md)
- [SIEM backends](siem-backends.md)
- [Attack scenarios](scenarios.md)
- [API reference](api.md)
- [GitHub Action](github-action.md)
