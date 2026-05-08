#!/usr/bin/env bash
set -euo pipefail

CHART_DIR="${1:-deploy/helm/ddos-samurai}"
RELEASE_NAME="${2:-samurai}"
NAMESPACE="${3:-default}"

if [[ ! -d "$CHART_DIR" ]]; then
  echo "[verify_helm] chart directory not found: $CHART_DIR" >&2
  exit 1
fi

run_helm() {
  if command -v helm >/dev/null 2>&1; then
    helm "$@"
    return 0
  fi
  if command -v docker >/dev/null 2>&1; then
    docker run --rm \
      -v "$(pwd)":/work \
      -w /work \
      alpine/helm:3.15.4 "$@"
    return 0
  fi
  echo "[verify_helm] helm or docker is required" >&2
  return 1
}

echo "[verify_helm] lint chart: $CHART_DIR"
run_helm lint "$CHART_DIR"

echo "[verify_helm] render chart: release=$RELEASE_NAME namespace=$NAMESPACE"
TMP_OUT="$(mktemp)"
run_helm template "$RELEASE_NAME" "$CHART_DIR" --namespace "$NAMESPACE" > "$TMP_OUT"

if [[ ! -s "$TMP_OUT" ]]; then
  echo "[verify_helm] rendered output is empty" >&2
  rm -f "$TMP_OUT"
  exit 1
fi

# Basic schema smoke: ensure at least master+slave workload rendered.
grep -q "kind: Deployment" "$TMP_OUT"
grep -q "app.kubernetes.io/component: master" "$TMP_OUT"
grep -Eq "kind: (Deployment|DaemonSet)" "$TMP_OUT"

echo "[verify_helm] ok"
rm -f "$TMP_OUT"
