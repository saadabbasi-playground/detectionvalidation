#!/usr/bin/env bash
# DetectionValidator — one-shot install script
# Usage:  bash <(curl -fsSL https://raw.githubusercontent.com/saadabbasi-playground/detectionvalidation/master/install.sh)
#    or:  git clone ... && cd detectionvalidation && bash install.sh
set -euo pipefail

REPO_URL="https://github.com/saadabbasi-playground/detectionvalidation.git"
INSTALL_DIR="${DV_INSTALL_DIR:-$HOME/detectionvalidation}"

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; RESET='\033[0m'
info()  { echo -e "${CYAN}[install]${RESET} $*"; }
ok()    { echo -e "${GREEN}[install]${RESET} $*"; }
warn()  { echo -e "${YELLOW}[install]${RESET} $*"; }
die()   { echo -e "${RED}[install] ERROR:${RESET} $*" >&2; exit 1; }

# ── Prerequisites ────────────────────────────────────────────────────────────

check_prereqs() {
    local missing=0

    # Docker
    if ! command -v docker &>/dev/null; then
        die "Docker not found. Install Docker Desktop: https://docs.docker.com/get-docker/"
    fi
    if ! docker info &>/dev/null 2>&1; then
        die "Docker daemon not running. Start Docker Desktop and try again."
    fi
    ok "Docker $(docker --version | awk '{print $3}' | tr -d ',')"

    # Python >= 3.12
    local py_bin=""
    for candidate in python3.12 python3.13 python3 python; do
        if command -v "$candidate" &>/dev/null; then
            local ver; ver="$("$candidate" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")' 2>/dev/null || echo "0.0")"
            local major="${ver%%.*}"; local minor="${ver##*.}"
            if [[ "$major" -ge 3 && "$minor" -ge 12 ]]; then
                py_bin="$candidate"
                break
            fi
        fi
    done
    [[ -n "$py_bin" ]] || die "Python 3.12+ not found. Install from https://python.org"
    ok "Python $("$py_bin" --version)"
    export PY_BIN="$py_bin"

    # Vagrant (optional — warn, don't fail)
    if ! command -v vagrant &>/dev/null; then
        warn "Vagrant not found — real auditd telemetry will be unavailable."
        warn "Install: brew install vagrant && vagrant plugin install vagrant-qemu"
    else
        ok "Vagrant $(vagrant --version | awk '{print $2}')"
        # vagrant-qemu plugin
        if ! vagrant plugin list 2>/dev/null | grep -q vagrant-qemu; then
            warn "vagrant-qemu plugin missing. Run: vagrant plugin install vagrant-qemu"
        else
            ok "vagrant-qemu plugin"
        fi
    fi
}

# ── Clone or update repo ─────────────────────────────────────────────────────

setup_repo() {
    # If we're already inside the repo, use the current directory
    if [[ -f "${PWD}/pyproject.toml" ]] && grep -q "detection-validator" "${PWD}/pyproject.toml" 2>/dev/null; then
        INSTALL_DIR="$PWD"
        info "Using existing repo at $INSTALL_DIR"
        return
    fi

    if [[ -d "$INSTALL_DIR/.git" ]]; then
        info "Repo already cloned at $INSTALL_DIR — pulling latest…"
        git -C "$INSTALL_DIR" pull --ff-only
    else
        info "Cloning into $INSTALL_DIR…"
        git clone "$REPO_URL" "$INSTALL_DIR"
    fi
}

# ── Create venv and install ──────────────────────────────────────────────────

setup_venv() {
    local venv_dir="$INSTALL_DIR/.venv"

    if command -v uv &>/dev/null; then
        info "Using uv (fast)"
        uv venv --python "$PY_BIN" "$venv_dir"
        uv pip install --python "$venv_dir/bin/python" -e "$INSTALL_DIR"
    else
        info "Using pip (install uv for faster setup: pip install uv)"
        "$PY_BIN" -m venv "$venv_dir"
        "$venv_dir/bin/pip" install --upgrade pip --quiet
        "$venv_dir/bin/pip" install -e "$INSTALL_DIR" --quiet
    fi

    ok "Package installed to $venv_dir"
}

# ── Wire 'dv' into PATH ──────────────────────────────────────────────────────

setup_path() {
    local bin_dir="$INSTALL_DIR/.venv/bin"
    local export_line="export PATH=\"$bin_dir:\$PATH\""

    # Detect active shell config files
    local configs=()
    [[ -f "$HOME/.zshrc" ]]         && configs+=("$HOME/.zshrc")
    [[ -f "$HOME/.bashrc" ]]        && configs+=("$HOME/.bashrc")
    [[ -f "$HOME/.bash_profile" ]]  && configs+=("$HOME/.bash_profile")
    [[ ${#configs[@]} -eq 0 ]]      && configs+=("$HOME/.profile")

    local added=false
    for cfg in "${configs[@]}"; do
        if ! grep -qF "$bin_dir" "$cfg" 2>/dev/null; then
            echo "" >> "$cfg"
            echo "# DetectionValidator" >> "$cfg"
            echo "$export_line" >> "$cfg"
            ok "Added PATH entry to $cfg"
            added=true
        else
            info "PATH already set in $cfg"
        fi
    done

    # Make dv available in the current shell immediately
    export PATH="$bin_dir:$PATH"
}

# ── Verify ───────────────────────────────────────────────────────────────────

verify() {
    if command -v dv &>/dev/null; then
        ok "'dv' is available: $(dv --version 2>/dev/null || echo 'ok')"
    else
        warn "'dv' not on PATH in this shell. Restart your terminal or run:"
        warn "  export PATH=\"$INSTALL_DIR/.venv/bin:\$PATH\""
    fi
}

# ── Main ─────────────────────────────────────────────────────────────────────

main() {
    echo ""
    echo -e "${CYAN}╔══════════════════════════════════════════════════╗${RESET}"
    echo -e "${CYAN}║       DetectionValidator — install               ║${RESET}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════╝${RESET}"
    echo ""

    check_prereqs
    setup_repo
    setup_venv
    setup_path
    verify

    echo ""
    ok "Installation complete!"
    echo ""
    echo -e "  ${CYAN}Next steps:${RESET}"
    echo -e "    Restart your terminal (or: ${CYAN}source ~/.zshrc${RESET})"
    echo ""
    echo -e "  ${CYAN}Quick start:${RESET}"
    echo -e "    ${CYAN}dv demo${RESET}                        # full end-to-end demo"
    echo -e "    ${CYAN}dv doctor${RESET}                      # environment pre-flight check"
    echo -e "    ${CYAN}dv doctor --canary${RESET}             # test telemetry pipeline"
    echo ""
    echo -e "  ${CYAN}External SIEM:${RESET}"
    echo -e "    ${CYAN}dv siem add prod --type opensearch --url https://... --username u --password p${RESET}"
    echo -e "    ${CYAN}dv siem test prod${RESET}"
    echo -e "    ${CYAN}dv siem attach prod${RESET}"
    echo -e "    ${CYAN}dv validate examples/detections/sigma/ --siem prod --since 1${RESET}"
    echo ""
}

main "$@"
