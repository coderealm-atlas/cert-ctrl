#!/usr/bin/env bash
set -euo pipefail
service_root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ $# -eq 0 || "$1" == "--help" || "$1" == "-h" ]]; then
  echo "Usage: ansible.sh {playbook|inventory|config|doc|galaxy|adhoc} [Ansible arguments...]"
  exit 0
fi
tool="$1"
shift
case "${tool}" in
  playbook|inventory|config|doc|galaxy) tool="ansible-${tool}" ;;
  adhoc) tool="ansible" ;;
  *) echo "Unknown Ansible command: ${tool}" >&2; exit 2 ;;
esac
source "${service_root}/scripts/ansible-env.sh"
cert_ctrl_require_ansible
exec "${CERT_CTRL_ANSIBLE_VENV}/bin/${tool}" "$@"
