#!/usr/bin/env bash
# DetectionValidator VM provisioning script.
# Installs auditd, Python3, and Vector on Ubuntu 22.04 ARM64.
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive

echo ">>> Updating packages..."
apt-get update -qq

echo ">>> Installing auditd and tools..."
apt-get install -y --no-install-recommends \
    auditd audispd-plugins \
    python3 python3-pip \
    curl wget netcat-openbsd \
    iproute2 procps sudo jq

echo ">>> Installing Vector (ARM64)..."
curl -1sLf 'https://setup.vector.dev' | bash
apt-get install -y vector

echo ">>> Configuring auditd..."
mkdir -p /var/log/audit /etc/audit/rules.d
# Enable auditd service
systemctl enable auditd
systemctl start auditd || true

echo ">>> Creating audit events JSONL directory..."
mkdir -p /var/log/audit
touch /var/log/audit/audit-events.jsonl
chmod 644 /var/log/audit/audit-events.jsonl

echo ">>> Creating victim user..."
id victim &>/dev/null || useradd -m -s /bin/bash victim

echo ">>> Provisioning complete. Config files will be installed next."
