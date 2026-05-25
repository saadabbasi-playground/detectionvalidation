# syntax=docker/dockerfile:1.7
# Ubuntu victim node — auditd + Python JSON converter → stdout → Vector
ARG UBUNTU_IMAGE=ubuntu:22.04
ARG TARGETPLATFORM=linux/arm64

FROM --platform=${TARGETPLATFORM} ${UBUNTU_IMAGE}

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update -qq && apt-get install -y --no-install-recommends \
    auditd \
    python3 \
    procps \
    iproute2 \
    curl \
    wget \
    netcat-openbsd \
    sudo \
    && rm -rf /var/lib/apt/lists/*

# Create non-root victim user (used to generate realistic process events)
RUN groupadd -r victim && useradd -r -g victim -u 1001 -m -s /bin/bash victim && \
    echo "victim ALL=(ALL) NOPASSWD: /bin/id, /usr/bin/id" >> /etc/sudoers

COPY audit.rules /etc/audit/rules.d/dv-audit.rules
COPY audit-to-json.py /opt/audit-to-json.py
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh /opt/audit-to-json.py

# Ensure audit log dir exists
RUN mkdir -p /var/log/audit

HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD pgrep -x auditd > /dev/null || pgrep -f audit-to-json > /dev/null || exit 1

ENTRYPOINT ["/entrypoint.sh"]
