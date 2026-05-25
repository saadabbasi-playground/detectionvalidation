#!/usr/bin/env bash
# Example: run a full attack-and-validate cycle against the Vagrant VM,
# then demonstrate offline matching and report generation.
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
RESULTS_JSON="/tmp/dv-results.json"
EVENTS_JSONL="/tmp/dv-events.jsonl"
REPORT_HTML="/tmp/dv-report.html"
REPORT_SARIF="/tmp/dv-scan.sarif"

echo "=== Step 1: Simulate attacks ==="
dv attack --cve CVE-2021-44228 --target vagrant --agent-port "$AGENT_PORT"
dv attack --cve CVE-2021-34527 --target vagrant --agent-port "$AGENT_PORT"
dv attack --cve CVE-2021-26855 --target vagrant --agent-port "$AGENT_PORT"

echo ""
echo "=== Step 2: Validate against live SIEM (last 1 hour) ==="
dv validate "$RULES_DIR" --siem opensearch --since 1 --format json -o "$RESULTS_JSON"

echo ""
echo "=== Step 3: Generate reports ==="
dv report --results "$RESULTS_JSON"                                        # CLI summary
dv report --results "$RESULTS_JSON" --format html  -o "$REPORT_HTML"      # HTML page
dv report --results "$RESULTS_JSON" --format sarif -o "$REPORT_SARIF"     # SARIF

echo ""
echo "=== Step 4: Match offline (no SIEM needed) ==="
vagrant ssh -c "sudo cat /var/log/audit/audit-events.jsonl" > "$EVENTS_JSONL" 2>/dev/null
dv match --events "$EVENTS_JSONL" "$RULES_DIR" --since 1 --format json | dv report

echo ""
echo "=== Step 5: CVE coverage analysis ==="
dv ingest "$RULES_DIR" -o /tmp/canonical.jsonl
dv map -i /tmp/canonical.jsonl -o /tmp/mapped.jsonl --mode hybrid
dv cve-coverage \
  --cve CVE-2021-44228,CVE-2021-34527,CVE-2021-26855 \
  --detections /tmp/mapped.jsonl

echo ""
echo "Done."
echo "  HTML report:           $REPORT_HTML"
echo "  SARIF file:            $REPORT_SARIF"
echo "  Raw events (JSONL):    $EVENTS_JSONL"
echo "  OpenSearch Dashboards: https://localhost:5601"
echo "  Splunk mock UI:        http://localhost:8000"
