#!/bin/bash
# Start auditd, load detection-validator rules, then stream JSON to stdout.
set -e

AUDIT_LOG="/var/log/audit/audit.log"
RULES="/etc/audit/rules.d/dv-audit.rules"

log() { echo "[entrypoint] $*" >&2; }

# Ensure audit log directory exists
mkdir -p /var/log/audit

# Attempt to start auditd and load rules.
# On Mac M1 (LinuxKit) the audit subsystem is available in the VM kernel,
# so this normally succeeds when the container has AUDIT_WRITE + AUDIT_CONTROL.
AUDITD_OK=false
if auditd -b 8192 -f 1 2>/dev/null; then
    AUDITD_OK=true
    sleep 1
    auditctl -R "$RULES" 2>&1 | while read -r line; do log "$line"; done || true
    log "auditd started, rules loaded from $RULES"
else
    log "WARNING: auditd could not attach to kernel audit subsystem."
    log "Running in synthetic-event mode (useful for pipeline testing)."
fi

# Hand off to the JSON converter — it handles both real and synthetic modes.
exec python3 /opt/audit-to-json.py "$AUDIT_LOG" "$AUDITD_OK"
