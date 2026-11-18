#!/usr/bin/env bash
# Ground truth for each node: CPU model and avx512vbmi from /proc/cpuinfo vs. the NFD label.
set -euo pipefail
source "$(dirname "$0")/lib.sh"

for role in server agent; do
  ip="$(tf_out "${role}_public_ip")"
  echo "== $role ($ip)"
  # -w matters: avx512_vbmi2 is a different flag.
  lab_ssh "$ip" '
    grep -m1 "model name" /proc/cpuinfo
    if grep -qw avx512vbmi /proc/cpuinfo; then echo "avx512vbmi: yes"; else echo "avx512vbmi: no"; fi
  '
done

echo
echo "== NFD labels (empty column = label not set = no VBMI or NFD not ready yet)"
KUBECONFIG="$KUBECONFIG_FILE" kubectl get nodes \
  -L kubernetes.io/arch \
  -L feature.node.kubernetes.io/cpu-cpuid.AVX512VBMI
