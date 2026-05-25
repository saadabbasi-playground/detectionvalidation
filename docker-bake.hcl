variable "REGISTRY" {
  default = "ghcr.io/detection-validator"
}

variable "TAG" {
  default = "dev"
}

variable "PUSH" {
  default = false
}

# ---------------------------------------------------------------------------
# Groups
# ---------------------------------------------------------------------------

group "default" {
  targets = ["core", "attacker", "linux-victim", "win-emulator", "atomic-runner"]
}

group "all" {
  targets = ["core", "attacker", "linux-victim", "win-victim", "win-emulator", "atomic-runner"]
}

group "lab" {
  targets = ["attacker", "linux-victim", "win-emulator", "atomic-runner"]
}

# ---------------------------------------------------------------------------
# Shared defaults
# ---------------------------------------------------------------------------

target "_base" {
  output = [PUSH ? "type=registry" : "type=cacheonly,mode=max"]
  cache-from = ["type=gha"]
  cache-to   = ["type=gha,mode=max"]
}

target "_multiarch" {
  inherits  = ["_base"]
  platforms = ["linux/amd64", "linux/arm64"]
}

target "_amd64-only" {
  inherits  = ["_base"]
  platforms = ["linux/amd64"]
}

# ---------------------------------------------------------------------------
# Image targets
# ---------------------------------------------------------------------------

target "core" {
  inherits   = ["_multiarch"]
  context    = "."
  dockerfile = "docker/core/Dockerfile"
  tags       = ["${REGISTRY}/core:${TAG}", "${REGISTRY}/core:latest"]
  labels = {
    "org.opencontainers.image.title"       = "detection-validator-core"
    "org.opencontainers.image.description" = "Detection Validator core service"
    "org.opencontainers.image.source"      = "https://github.com/detection-validator/detection-validator"
  }
}

target "attacker" {
  inherits   = ["_multiarch"]
  context    = "docker/attacker"
  dockerfile = "Dockerfile"
  tags       = ["${REGISTRY}/attacker:${TAG}"]
  labels = {
    "org.opencontainers.image.title" = "detection-validator-attacker"
  }
}

target "linux-victim" {
  inherits   = ["_multiarch"]
  context    = "docker/linux-victim"
  dockerfile = "Dockerfile"
  tags       = ["${REGISTRY}/linux-victim:${TAG}"]
  labels = {
    "org.opencontainers.image.title" = "detection-validator-linux-victim"
  }
}

# Windows containers require an amd64 Windows Docker host — only build/push on demand.
target "win-victim" {
  inherits   = ["_amd64-only"]
  context    = "docker/win-victim"
  dockerfile = "Dockerfile"
  tags       = ["${REGISTRY}/win-victim:${TAG}"]
  labels = {
    "org.opencontainers.image.title" = "detection-validator-win-victim"
  }
}

target "win-emulator" {
  inherits   = ["_multiarch"]
  context    = "docker/win-emulator"
  dockerfile = "Dockerfile"
  tags       = ["${REGISTRY}/win-emulator:${TAG}"]
  labels = {
    "org.opencontainers.image.title" = "detection-validator-win-emulator"
  }
}

target "atomic-runner" {
  inherits   = ["_multiarch"]
  context    = "docker/atomic-runner"
  dockerfile = "Dockerfile"
  tags       = ["${REGISTRY}/atomic-runner:${TAG}"]
  labels = {
    "org.opencontainers.image.title" = "detection-validator-atomic-runner"
  }
}
