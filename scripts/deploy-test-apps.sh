#!/usr/bin/env bash
# Deploy (default) or delete the java4shell test workloads.
#   scripts/deploy-test-apps.sh          # apply + wait
#   scripts/deploy-test-apps.sh delete   # remove namespace java-lab
set -euo pipefail
source "$(dirname "$0")/lib.sh"
export KUBECONFIG="${KUBECONFIG:-$KUBECONFIG_FILE}"

MANIFEST="$ROOT_DIR/manifests/test-apps.yaml"

if [[ "${1:-}" == "delete" ]]; then
  kubectl delete -f "$MANIFEST" --ignore-not-found
  exit 0
fi

kubectl apply -f "$MANIFEST"
# First run pulls ~200 MB images per node; give it time.
for d in vuln vuln-mitigated not-affected; do
  kubectl -n java-lab rollout status "deployment/$d" --timeout=5m
done
kubectl -n java-lab get pods -o wide
