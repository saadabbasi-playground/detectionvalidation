# Deployment Guides

Per-platform deployment instructions for connecting detection-validator to your SIEM.

| Platform | Guide |
|---|---|
| Splunk Enterprise / Cloud | [splunk.md](splunk.md) |
| OpenSearch / OSDP | [opensearch.md](opensearch.md) |
| Elasticsearch / Elastic Security | [elastic.md](elastic.md) |
| Microsoft Sentinel | [sentinel.md](sentinel.md) |
| Google Chronicle / SecOps | [chronicle.md](chronicle.md) |
| Wazuh | [wazuh.md](wazuh.md) |

## Quick start

```bash
# Test connectivity to your SIEM
./dv doctor --siem <name>

# Deploy rules
./dv deploy --siem <name> --rules ./detections/
```
