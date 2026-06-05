# syntax=docker/dockerfile:1.7
# detection-validator live-capture runner
#
# Installs Sysmon for Linux (eBPF-based) and runs one Atomic Red Team atomic,
# capturing the resulting Sysmon events as JSONL on stdout.
#
# Build (multi-arch):
#   docker buildx build --platform linux/amd64,linux/arm64 -t detection-validator-runner:latest .
#
# Run (requires --privileged for eBPF):
#   docker run --rm --privileged -e TECHNIQUE_ID=T1059.004 detection-validator-runner:latest
#
# NOTE: eBPF requires kernel ≥ 5.8 on the host. Docker Desktop on Apple Silicon
# does NOT expose eBPF to containers — use `--source replay` on macOS.

ARG TARGETPLATFORM
ARG BUILDPLATFORM

FROM --platform=${TARGETPLATFORM:-linux/amd64} ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# ── System packages ───────────────────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        wget \
        gnupg2 \
        rsyslog \
        python3 \
        python3-pip \
    && rm -rf /var/lib/apt/lists/*

# ── Python dependencies ───────────────────────────────────────────────────────
RUN pip3 install --no-cache-dir pyyaml

# ── Sysmon for Linux ──────────────────────────────────────────────────────────
# Microsoft packages repository provides sysmonforlinux for amd64 and arm64.
RUN wget -q https://packages.microsoft.com/config/ubuntu/22.04/packages-microsoft-prod.deb \
        -O /tmp/packages-microsoft-prod.deb \
    && dpkg -i /tmp/packages-microsoft-prod.deb \
    && rm /tmp/packages-microsoft-prod.deb \
    && apt-get update \
    && apt-get install -y --no-install-recommends sysmonforlinux \
    && rm -rf /var/lib/apt/lists/*

# ── rsyslog configuration ─────────────────────────────────────────────────────
COPY rsyslog-sysmon.conf /etc/rsyslog.d/10-sysmon.conf

# ── Sysmon config ─────────────────────────────────────────────────────────────
RUN mkdir -p /etc/sysmon
COPY sysmon-config.xml /etc/sysmon/config.xml

# ── Entrypoint ────────────────────────────────────────────────────────────────
COPY entrypoint.py /entrypoint.py
RUN chmod +x /entrypoint.py

# Sysmon events go to stderr; JSONL events go to stdout.
ENTRYPOINT ["python3", "/entrypoint.py"]
