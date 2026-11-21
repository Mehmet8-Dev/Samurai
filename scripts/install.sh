#!/usr/bin/env bash
# Samurai One-Command Installer (Zero-Build Binary Release or Docker Runtime)
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/Mehmet8-Dev/Samurai/main/scripts/install.sh | bash
#   ./scripts/install.sh --client claude_code --yes
#   ./scripts/install.sh --docker --client cursor --yes

set -euo pipefail

REPO="${SAMURAI_REPO:-Mehmet8-Dev/Samurai}"
VERSION="${SAMURAI_VERSION:-latest}"
IMAGE="${SAMURAI_IMAGE:-ghcr.io/mehmet8-dev/samurai:latest}"
PREFIX="${SAMURAI_INSTALL_DIR:-$HOME/.local/bin}"
MODE="auto"
CLIENT=""
APPLY_SETUP=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --docker) MODE="docker"; shift ;;
    --binary) MODE="binary"; shift ;;
    --version) VERSION="${2:-latest}"; shift 2 ;;
    --prefix) PREFIX="${2:-$HOME/.local/bin}"; shift 2 ;;
    --client) CLIENT="${2:-}"; shift 2 ;;
    --yes|-y) APPLY_SETUP=1; shift ;;
    -h|--help)
      cat <<'EOF'
Samurai Installer

Options:
  --binary          Install pre-built Linux x86_64 release binaries (default on Linux x86_64)
  --docker          Pull GHCR container image and install a lightweight wrapper (default on macOS/other)
  --version TAG     Release tag (e.g. v3.3.0 or latest)
  --prefix DIR      Binary install directory (default: ~/.local/bin)
  --client ID       Optionally run `samurai_mcp setup --client ID` after install
  --yes, -y         Apply MCP client config changes (without --yes, setup runs as --dry-run)
EOF
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      exit 2
      ;;
  esac
done

OS="$(uname -s)"
ARCH="$(uname -m)"

if [[ "$MODE" == "auto" ]]; then
  if [[ "$OS" == "Linux" && "$ARCH" == "x86_64" ]]; then
    MODE="binary"
  else
    MODE="docker"
  fi
fi

mkdir -p "$PREFIX"

if [[ "$MODE" == "binary" ]]; then
  if [[ "$OS" != "Linux" || "$ARCH" != "x86_64" ]]; then
    echo "Pre-built native release tarballs currently target Linux x86_64; use --docker on ${OS}/${ARCH}." >&2
    exit 1
  fi

  if [[ "$VERSION" == "latest" ]]; then
    VERSION="$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
      | awk -F'"' '/"tag_name":/{print $4; exit}')"
    if [[ -z "$VERSION" ]]; then
      echo "Could not resolve latest release tag from GitHub; falling back to --docker mode." >&2
      MODE="docker"
    fi
  fi
fi

if [[ "$MODE" == "binary" ]]; then
  TARBALL="samurai-${VERSION}-linux-x86_64.tar.gz"
  BASE_URL="https://github.com/${REPO}/releases/download/${VERSION}"
  TMP_DIR="$(mktemp -d)"
  trap 'rm -rf "$TMP_DIR"' EXIT

  echo "[samurai] Downloading ${TARBALL}..."
  curl -fL --progress-bar "${BASE_URL}/${TARBALL}" -o "${TMP_DIR}/${TARBALL}"
  if curl -fsSL "${BASE_URL}/${TARBALL}.sha256" -o "${TMP_DIR}/${TARBALL}.sha256"; then
    (cd "$TMP_DIR" && sha256sum -c "${TARBALL}.sha256")
  fi

  tar -xzf "${TMP_DIR}/${TARBALL}" -C "$TMP_DIR"
  SRC_BIN="${TMP_DIR}/samurai-${VERSION}-linux-x86_64/bin"
  install -m 0755 "${SRC_BIN}"/* "$PREFIX/"
  echo "[samurai] Installed native binaries into ${PREFIX}"

  if [[ -n "$CLIENT" ]]; then
    SETUP_ARGS=("${PREFIX}/samurai_mcp" "setup" "--client" "$CLIENT")
    [[ "$APPLY_SETUP" -eq 1 ]] && SETUP_ARGS+=("--yes") || SETUP_ARGS+=("--dry-run")
    "${SETUP_ARGS[@]}"
  else
    "${PREFIX}/samurai_mcp" doctor || true
  fi
fi

if [[ "$MODE" == "docker" ]]; then
  if ! command -v docker >/dev/null 2>&1; then
    echo "Docker is required for --docker mode on ${OS}/${ARCH}. Install Docker Desktop or Docker Engine first." >&2
    exit 1
  fi
  echo "[samurai] Pulling ${IMAGE}..."
  docker pull "$IMAGE"

  NET_FLAG="--network host"
  if [[ "$OS" != "Linux" ]]; then
    NET_FLAG="--add-host host.docker.internal:host-gateway"
  fi

  cat > "${PREFIX}/samurai" <<EOF
#!/usr/bin/env bash
exec docker run --rm -i ${NET_FLAG} "${IMAGE}" samurai "\$@"
EOF
  cat > "${PREFIX}/samurai_mcp" <<EOF
#!/usr/bin/env bash
if [[ "\${1:-}" == "setup" || "\${1:-}" == "doctor" ]]; then
  exec docker run --rm -i -u "\$(id -u):\$(id -g)" -v "\$HOME:\$HOME" -v "\$(pwd):\$(pwd)" -w "\$(pwd)" -e HOME="\$HOME" "${IMAGE}" samurai_mcp "\$@"
fi
exec docker run --rm -i ${NET_FLAG} "${IMAGE}" samurai_mcp "\$@"
EOF
  chmod 0755 "${PREFIX}/samurai" "${PREFIX}/samurai_mcp"
  echo "[samurai] Installed Docker wrapper commands into ${PREFIX}/samurai and ${PREFIX}/samurai_mcp"
  if [[ "$OS" != "Linux" ]]; then
    echo "[samurai] Note for macOS/Windows: target host services via host.docker.internal (or publish ports with -p) since Docker Desktop runs in a VM."
  fi

  if [[ -n "$CLIENT" ]]; then
    SETUP_FLAG="--dry-run"
    [[ "$APPLY_SETUP" -eq 1 ]] && SETUP_FLAG="--yes"
    "${PREFIX}/samurai_mcp" setup --docker --client "$CLIENT" "$SETUP_FLAG"
  fi
fi

case ":${PATH}:" in
  *":${PREFIX}:"*) ;;
  *) echo "[samurai] Add ${PREFIX} to your PATH: export PATH=\"${PREFIX}:\$PATH\"" ;;
esac
