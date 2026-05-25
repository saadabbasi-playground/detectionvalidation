.PHONY: install test lint build run-example doctor clean pin-digests

PYTHON  := python3
UV      := uv
REGISTRY ?= ghcr.io/detection-validator
TAG      ?= dev

install:
	$(UV) sync --extra dev

test:
	$(UV) run pytest

lint:
	$(UV) run ruff check src/
	$(UV) run ruff format --check src/

format:
	$(UV) run ruff check --fix src/
	$(UV) run ruff format src/

build:
	docker buildx bake --file docker-bake.hcl

build-push:
	PUSH=true TAG=$(TAG) docker buildx bake --file docker-bake.hcl

run-example:
	$(UV) run detection-validator validate --help

doctor:
	./dv doctor

# Update all Dockerfile FROM digest pins
pin-digests:
	@echo "Pinning base image digests..."
	@scripts/pin-digests.sh

clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -name "*.pyc" -delete
	rm -rf .pytest_cache .ruff_cache dist build

.PHONY: agent
agent:
	cd agent && go build -o bin/dv-agent ./...

agent-test:
	cd agent && go test ./...
