# detection-validator docs

Multi-SIEM detection validation platform.

## Getting started

```bash
# Prerequisites: Docker 24+, docker compose v2
./dv doctor
./dv up core
./dv validate --rules ./detections/ --siem opensearch
```

## Sections

- [Architecture](architecture.md)
- [Docker images](docker-images.md)
- [Configuration](configuration.md)
- [SIEM backends](siem-backends.md)
- [Attack scenarios](scenarios.md)
- [API reference](api.md)
- [GitHub Action](github-action.md)
