# syntax=docker/dockerfile:1.7
# Linux container that emulates Windows Sysmon events from a script library.
# Used on ARM64 (M1/M2/Pi) as a drop-in fallback for win-victim.
# Emits Sysmon-structured JSON events to stdout / a shared log volume.
ARG PYTHON_IMAGE=python:3.12-slim
ARG BUILDPLATFORM
ARG TARGETPLATFORM

FROM --platform=${BUILDPLATFORM} ${PYTHON_IMAGE} AS builder

WORKDIR /build
RUN pip install --no-cache-dir uv==0.4.10

COPY win-emulator/requirements.txt ./requirements.txt
RUN uv pip install --system --no-cache -r requirements.txt

# ---- runtime ---------------------------------------------------------------
FROM --platform=${TARGETPLATFORM} ${PYTHON_IMAGE} AS runtime

RUN groupadd -r emulator && useradd -r -g emulator -u 1002 -m emulator

COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages

WORKDIR /app
COPY win-emulator/ .

RUN chown -R emulator:emulator /app
USER emulator

ENV EMULATOR_OUTPUT_DIR=/var/log/sysmon \
    EMULATOR_SCENARIO=baseline \
    EMULATOR_RATE=1.0

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import emulator; emulator.health_check()" || exit 1

ENTRYPOINT ["python", "-m", "emulator"]
CMD ["--help"]
