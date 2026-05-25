# detection-validator

Multi-SIEM detection validation platform. Validate detection rules against live
or synthetic attack telemetry, map coverage to MITRE ATT\&CK, and surface gaps.

```
./dv up lab --siem opensearch
./dv validate --rules ./detections/ --siem opensearch --format sarif
./dv report --format cli
```

## Prerequisites

| Requirement | Version |
|---|---|
| Docker | ≥ 24 |
| docker compose | v2 |
| docker buildx | any |
| Python | 3.12 (host dev only) |
| uv | latest |

```bash
./dv doctor          # check everything
```

## Quick start

```bash
# 1. Start the core service
./dv up core

# 2. Start the full lab (attacker + victims + atomic-runner)
./dv up lab --siem opensearch --profile standard

# 3. Run validation
./dv validate --rules ./detections/

# 4. Generate a SARIF report for GitHub Code Scanning
./dv report --format sarif --output results.sarif
```

## Architecture

```
┌─ core ──────────────────────────────────────────────────────────┐
│  detection_validator  (FastAPI + Celery)                         │
│  parsers ▸ normalizer ▸ validator ▸ coverage ▸ reporters        │
└──────────────────────────────────────────────────────────────────┘
        │                    │                    │
┌─ lab ─┴──────┐    ┌────────┴──────┐    ┌───────┴──────────────┐
│  attacker    │    │  linux-victim │    │  atomic-runner        │
│  (Kali-slim) │    │  (auditd +    │    │  (invoke-atomicredteam│
│  nuclei,ART  │    │   Sysmon,Falco│    │   + ART library)     │
└──────────────┘    └───────────────┘    └──────────────────────┘
        │
┌─ siem ─┴──────────────────────────────────────────────────────┐
│  opensearch / elastic / splunk / sentinel / chronicle / wazuh  │
│  + vector (shipper)  + grafana (dashboards)                    │
└────────────────────────────────────────────────────────────────┘
```

## Multi-architecture

| Platform | Windows victim | Notes |
|---|---|---|
| amd64 (x86_64) | `win-victim` (real container) | Requires Windows container daemon |
| arm64 (M1/M2/Pi) | `win-emulator` (auto) | Trade-off banner printed on first `up` |

Override: `./dv up lab --windows container|emulator|external|none`

## Resource profiles

```bash
./dv up lab --profile tiny      # ≤1 GB RAM, Pi / free CI
./dv up lab --profile standard  # 4 GB RAM, dev workstation
./dv up lab --profile full      # 8 GB+ RAM, all services
```

## Composable SIEM

```bash
# Single SIEM
./dv up lab --siem opensearch

# Dual-write
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
no local setup required.

## License

Apache 2.0
