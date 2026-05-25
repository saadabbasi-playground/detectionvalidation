#!/usr/bin/env bash
# Post-create script for GitHub Codespaces / devcontainer
set -euo pipefail

echo "==> Installing uv..."
curl -LsSf https://astral.sh/uv/install.sh | sh
export PATH="$HOME/.cargo/bin:$PATH"

echo "==> Setting up Python environment..."
uv sync --extra dev

echo "==> Setting up Docker Buildx multi-arch builder..."
docker buildx create \
  --name multiarch \
  --driver docker-container \
  --use \
  --bootstrap 2>/dev/null || docker buildx use multiarch

echo "==> Making ./dv executable..."
chmod +x ./dv

echo ""
echo "detection-validator devcontainer ready."
echo "Run: ./dv doctor"
