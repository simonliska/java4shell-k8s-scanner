#!/usr/bin/env bash
# Copy the k3s kubeconfig from the server to ./kubeconfig, pointed at its public IP.
set -euo pipefail
source "$(dirname "$0")/lib.sh"

SERVER_IP="$(tf_out server_public_ip)"

echo "Waiting for k3s on $SERVER_IP (first boot takes ~1-3 min)..."
for i in $(seq 1 40); do
  if lab_ssh "$SERVER_IP" test -f /etc/rancher/k3s/k3s.yaml 2>/dev/null; then
    break
  fi
  [[ $i -eq 40 ]] && { echo "Timed out. Check: ssh ... sudo cat /var/log/k3s-bootstrap.log"; exit 1; }
  sleep 10
done

lab_ssh "$SERVER_IP" cat /etc/rancher/k3s/k3s.yaml \
  | sed "s#https://127.0.0.1:6443#https://$SERVER_IP:6443#" \
  > "$KUBECONFIG_FILE"
chmod 600 "$KUBECONFIG_FILE"

echo "Wrote $KUBECONFIG_FILE"
