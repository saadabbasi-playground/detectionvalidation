# syntax=docker/dockerfile:1.7
# Kali-slim with Atomic Red Team runner, Caldera client, and nuclei.
# Pin digests: run `make pin-digests` to update.
ARG KALI_IMAGE=kalilinux/kali-rolling:latest
ARG BUILDPLATFORM
ARG TARGETPLATFORM

FROM --platform=${BUILDPLATFORM} ${KALI_IMAGE} AS builder

ARG NUCLEI_VERSION=3.2.9
ARG TARGETARCH

# Install build dependencies for nuclei (pre-built binary download)
RUN apt-get update -qq && apt-get install -y --no-install-recommends \
    curl ca-certificates unzip git ruby ruby-dev build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install nuclei
RUN ARCH=$([ "${TARGETARCH}" = "arm64" ] && echo "arm64" || echo "amd64") && \
    curl -fsSL "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_${ARCH}.zip" \
      -o /tmp/nuclei.zip && \
    unzip /tmp/nuclei.zip nuclei -d /usr/local/bin/ && \
    chmod +x /usr/local/bin/nuclei && \
    rm /tmp/nuclei.zip

# Install Atomic Red Team invoke-atomicredteam (Ruby port for Linux)
RUN gem install invoke_atomic_red_team --no-document 2>/dev/null || true

# ---- runtime ---------------------------------------------------------------
FROM --platform=${TARGETPLATFORM} ${KALI_IMAGE} AS runtime

RUN apt-get update -qq && apt-get install -y --no-install-recommends \
    curl nmap netcat-openbsd python3 python3-pip ruby git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/local/bin/nuclei /usr/local/bin/nuclei
COPY --from=builder /var/lib/gems /var/lib/gems
COPY --from=builder /usr/local/bin/invoke_atomic* /usr/local/bin/ 2>/dev/null || true

RUN groupadd -r attacker && useradd -r -g attacker -u 1000 -m attacker

WORKDIR /home/attacker
COPY scripts/ /home/attacker/scripts/ 2>/dev/null || true

USER attacker

HEALTHCHECK --interval=60s --timeout=15s --start-period=30s --retries=2 \
    CMD nuclei -version || exit 1

ENTRYPOINT ["/bin/bash"]
