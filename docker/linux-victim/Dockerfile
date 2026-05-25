# syntax=docker/dockerfile:1.7
# Ubuntu victim node with auditd, Sysmon for Linux, and Falco.
# Pin digests: run `make pin-digests` to update.
ARG UBUNTU_IMAGE=ubuntu:24.04
ARG BUILDPLATFORM
ARG TARGETPLATFORM

FROM --platform=${BUILDPLATFORM} ${UBUNTU_IMAGE} AS downloader

ARG SYSMON_VERSION=1.3.3
ARG TARGETARCH

RUN apt-get update -qq && apt-get install -y --no-install-recommends \
    curl ca-certificates && rm -rf /var/lib/apt/lists/*

# Download Sysmon for Linux binary
RUN ARCH=$([ "${TARGETARCH}" = "arm64" ] && echo "arm64" || echo "x86_64") && \
    curl -fsSL \
      "https://github.com/Sysinternals/SysmonForLinux/releases/download/${SYSMON_VERSION}/sysmon_${SYSMON_VERSION}_linux_${ARCH}.tar.gz" \
      -o /tmp/sysmon.tar.gz 2>/dev/null || \
    curl -fsSL \
      "https://packages.microsoft.com/repos/microsoft-ubuntu-noble-prod/pool/main/s/sysmonforlinux/sysmonforlinux_${SYSMON_VERSION}_${ARCH}.deb" \
      -o /tmp/sysmon.deb 2>/dev/null || true

# ---- runtime ---------------------------------------------------------------
FROM --platform=${TARGETPLATFORM} ${UBUNTU_IMAGE} AS runtime

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update -qq && apt-get install -y --no-install-recommends \
    auditd audispd-plugins \
    curl ca-certificates gnupg \
    python3 python3-pip \
    rsyslog \
    && rm -rf /var/lib/apt/lists/*

# Install Falco via apt (official repo)
RUN curl -fsSL https://falco.org/repo/falcosecurity-packages.asc | \
    gpg --dearmor -o /usr/share/keyrings/falco-archive-keyring.gpg && \
    echo "deb [signed-by=/usr/share/keyrings/falco-archive-keyring.gpg] \
      https://download.falco.org/packages/deb stable main" \
      > /etc/apt/sources.list.d/falcosecurity.list && \
    apt-get update -qq && \
    apt-get install -y --no-install-recommends falco || true && \
    rm -rf /var/lib/apt/lists/*

COPY --from=downloader /tmp/sysmon* /opt/sysmon/ 2>/dev/null || true
COPY configs/audit.rules /etc/audit/rules.d/dv-audit.rules 2>/dev/null || true

RUN groupadd -r victim && useradd -r -g victim -u 1001 -m victim

HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD pgrep auditd || exit 1

ENTRYPOINT ["/usr/sbin/auditd"]
CMD ["-f", "-l"]
