#!/usr/bin/env bash
# Destroy the lab and check nothing billable is left behind.
set -euo pipefail
source "$(dirname "$0")/lib.sh"

terraform -chdir="$TF_DIR" destroy -input=false "$@"
rm -f "$KUBECONFIG_FILE"

echo "Checking for leftover lab instances/volumes in $REGION..."
instances=$(aws ec2 describe-instances --region "$REGION" \
  --filters Name=tag:Project,Values=java4shell-lab Name=instance-state-name,Values=pending,running,stopping,stopped \
  --query 'Reservations[].Instances[].InstanceId' --output text)
volumes=$(aws ec2 describe-volumes --region "$REGION" \
  --filters Name=tag:Project,Values=java4shell-lab \
  --query 'Volumes[].VolumeId' --output text)

if [[ -z "$instances" && -z "$volumes" ]]; then
  echo "Clean: no lab instances or volumes left."
else
  echo "WARNING: leftovers found -> instances: ${instances:-none}, volumes: ${volumes:-none}"
  exit 1
fi
