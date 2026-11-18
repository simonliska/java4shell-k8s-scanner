# Shared settings for lab scripts. Source it, don't run it.
# shellcheck shell=bash

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Local, gitignored overrides (e.g. AWS_PROFILE=...). Terraform and the aws CLI both read AWS_PROFILE.
if [[ -f "$ROOT_DIR/.env" ]]; then
  set -a
  # shellcheck source=/dev/null
  source "$ROOT_DIR/.env"
  set +a
fi

TF_DIR="$ROOT_DIR/terraform"
KUBECONFIG_FILE="$ROOT_DIR/kubeconfig"
SSH_KEY="${SSH_KEY:-$HOME/.ssh/vbmi-key.pem}"
REGION="${AWS_REGION:-eu-central-1}"

# Lab IPs change every run, so don't pollute known_hosts (throwaway hosts only).
SSH_OPTS=(-i "$SSH_KEY" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o ConnectTimeout=10)

tf_out() { terraform -chdir="$TF_DIR" output -raw "$1"; }

lab_ssh() {
  local host="$1"
  shift
  ssh "${SSH_OPTS[@]}" "ec2-user@$host" "$@"
}
