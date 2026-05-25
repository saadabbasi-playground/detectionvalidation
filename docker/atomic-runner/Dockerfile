# syntax=docker/dockerfile:1.7
# Lightweight container that executes Atomic Red Team tests against victim nodes.
# Ships with invoke-atomicredteam and the full atomics library.
ARG PYTHON_IMAGE=python:3.12-slim
ARG BUILDPLATFORM
ARG TARGETPLATFORM

FROM --platform=${BUILDPLATFORM} ${PYTHON_IMAGE} AS builder

WORKDIR /build
RUN pip install --no-cache-dir uv==0.4.10

# Python wrapper for ART execution
RUN uv pip install --system --no-cache \
    "atomic-operator>=0.22" \
    "requests>=2.31" \
    "pyyaml>=6.0" \
    "rich>=13.0" \
    "click>=8.1"

# Download Atomic Red Team library
ARG ART_VERSION=master
RUN apt-get update -qq && apt-get install -y --no-install-recommends git && \
    git clone --depth 1 --branch ${ART_VERSION} \
      https://github.com/redcanaryco/atomic-red-team.git /art && \
    rm -rf /art/.git && \
    apt-get purge -y git && rm -rf /var/lib/apt/lists/*

# ---- runtime ---------------------------------------------------------------
FROM --platform=${TARGETPLATFORM} ${PYTHON_IMAGE} AS runtime

RUN apt-get update -qq && apt-get install -y --no-install-recommends \
    curl wget ca-certificates && rm -rf /var/lib/apt/lists/*

RUN groupadd -r runner && useradd -r -g runner -u 1003 -m runner

COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin
COPY --from=builder /art /opt/atomic-red-team

WORKDIR /app
COPY runner/ ./ 2>/dev/null || true

RUN chown -R runner:runner /app
USER runner

ENV ART_PATH=/opt/atomic-red-team \
    RUNNER_TARGET_HOST=linux-victim \
    RUNNER_TARGET_PORT=22

HEALTHCHECK --interval=60s --timeout=10s --start-period=10s --retries=2 \
    CMD python -c "import atomic_operator; print('ok')" || exit 1

ENTRYPOINT ["python", "-m", "runner"]
CMD ["--help"]
