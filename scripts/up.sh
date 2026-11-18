#!/usr/bin/env bash
# Create the 2-node k3s lab, fetch kubeconfig, wait for nodes. Costs ~$0.065/h until down.sh.
set -euo pipefail
source "$(dirname "$0")/lib.sh"

[[ -f "$SSH_KEY" ]] || { echo "SSH key not found: $SSH_KEY (set SSH_KEY=...)"; exit 1; }

terraform -chdir="$TF_DIR" init -input=false
terraform -chdir="$TF_DIR" apply -input=false "$@"

"$ROOT_DIR/scripts/kubeconfig.sh"

export KUBECONFIG="$KUBECONFIG_FILE"
echo "Waiting for 2 nodes to register..."
for i in $(seq 1 60); do
  [[ "$(kubectl get nodes --no-headers 2>/dev/null | wc -l | tr -d ' ')" -ge 2 ]] && break
  sleep 10
done
kubectl wait --for=condition=Ready node --all --timeout=5m
kubectl get nodes -o wide

cat <<EOF

Lab is up. Remember: scripts/down.sh when finished.
  export KUBECONFIG=$KUBECONFIG_FILE
  scripts/check-vbmi.sh
EOF
