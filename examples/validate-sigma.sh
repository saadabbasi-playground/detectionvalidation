#!/usr/bin/env bash
# Example: run a full attack-and-validate cycle against the Vagrant VM.
#
# Usage:
#   ./examples/validate-sigma.sh                     # uses examples/detections/sigma/
#   ./examples/validate-sigma.sh path/to/my/rules/
#
# Prerequisites:
#   - SIEM stack running:  ./dv up lab --siem opensearch --profile tiny
#   - Vagrant VM running:  cd vagrant && vagrant up
#   - Virtual env active:  source .venv/bin/activate
set -euo pipefail

RULES_DIR="${1:-./examples/detections/sigma}"
AGENT_PORT="${AGENT_PORT:-9098}"

echo "=== Step 1: Simulate attacks ==="
dv attack --cve CVE-2021-44228 --target vagrant --agent-port "$AGENT_PORT"
dv attack --cve CVE-2021-34527 --target vagrant --agent-port "$AGENT_PORT"
dv attack --cve CVE-2021-26855 --target vagrant --agent-port "$AGENT_PORT"

echo ""
echo "=== Step 2: Validate detections (last 1 hour) ==="
dv validate "$RULES_DIR" --siem opensearch --since 1

echo ""
echo "=== Step 3: CVE coverage analysis ==="
dv ingest "$RULES_DIR" -o /tmp/canonical.jsonl
dv map -i /tmp/canonical.jsonl -o /tmp/mapped.jsonl --mode hybrid
dv cve-coverage \
  --cve CVE-2021-44228,CVE-2021-34527,CVE-2021-26855 \
  --detections /tmp/mapped.jsonl

echo ""
echo "Done."
echo "  OpenSearch Dashboards: https://localhost:5601"
echo "  Splunk mock UI:        http://localhost:8000"
