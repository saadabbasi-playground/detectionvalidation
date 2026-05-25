# syntax=docker/dockerfile:1.7
# Atomic Red Team scenario runner — executes CVE-mapped attack simulations
# against dv-linux-victim via its HTTP agent API.
ARG PYTHON_IMAGE=python:3.12-slim
ARG TARGETPLATFORM=linux/arm64

FROM --platform=${TARGETPLATFORM} ${PYTHON_IMAGE}

ENV DEBIAN_FRONTEND=noninteractive

RUN pip install --no-cache-dir requests pyyaml rich click

RUN groupadd -r runner && useradd -r -g runner -u 1003 -m runner

WORKDIR /app
COPY runner.py techniques.py ./
COPY scenarios/ /scenarios/
RUN chown -R runner:runner /app

USER runner

ENV RUNNER_TARGET_HOST=linux-victim \
    RUNNER_AGENT_PORT=9099

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python -c "import requests; requests.get('http://linux-victim:9099/health', timeout=3)" || exit 1

ENTRYPOINT ["python", "runner.py"]
CMD ["--help"]
