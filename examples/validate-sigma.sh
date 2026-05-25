#!/usr/bin/env bash
# Example: validate a directory of Sigma rules against OpenSearch.
set -euo pipefail

RULES_DIR="${1:-./examples/sigma-rules}"

echo "Starting validation lab..."
./dv up core --siem opensearch --profile tiny

echo "Running validation..."
./dv validate --rules "$RULES_DIR" --siem opensearch --format sarif --output results.sarif

echo "Generating report..."
./dv report --format cli

echo "Done. results.sarif written."
