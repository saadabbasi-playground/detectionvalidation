# syntax=docker/dockerfile:1.7
# Pin digests: run `make pin-digests` to update.
# Builder uses BUILDPLATFORM for native compilation speed; final image uses TARGETPLATFORM.
ARG PYTHON_IMAGE=python:3.12-slim
ARG BUILDPLATFORM
ARG TARGETPLATFORM

# ---- builder ---------------------------------------------------------------
FROM --platform=${BUILDPLATFORM} ${PYTHON_IMAGE} AS builder

WORKDIR /build

# Install uv for fast dependency resolution
RUN pip install --no-cache-dir uv==0.4.10

# Leverage layer caching: copy manifests before source
COPY pyproject.toml ./
COPY src/ ./src/

# Install into system python so it can be copied cleanly to runtime stage
RUN uv pip install --system --no-cache .

# ---- runtime ---------------------------------------------------------------
FROM --platform=${TARGETPLATFORM} ${PYTHON_IMAGE} AS runtime

RUN groupadd -r dv && useradd -r -g dv -u 1000 -m dv

# Copy installed packages and entry-point scripts from builder
COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=builder /usr/local/bin/detection-validator /usr/local/bin/detection-validator 2>/dev/null || true

USER dv
WORKDIR /app

HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD python -c "import detection_validator; detection_validator.health_check()" || exit 1

ENTRYPOINT ["detection-validator"]
CMD ["--help"]
