#!/usr/bin/env bash
# Shared by setup, direct CLI, and deployment entry points. Sourcing is inert.
cert_ctrl_ansible_paths() {
  local service_root
  service_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
  CERT_CTRL_ANSIBLE_DIR="${service_root}/ansible"
  CERT_CTRL_ANSIBLE_VENV="$(cd "${service_root}/.." && pwd)/.venv-ansible"
  CERT_CTRL_ANSIBLE_SETUP="${service_root}/setup-ansible.sh"
}

cert_ctrl_ansible_exports() {
  # Isolate Python and collections even when another virtualenv is active.
  unset PYTHONHOME PYTHONPATH
  export PYTHONNOUSERSITE=1
  export PATH="${CERT_CTRL_ANSIBLE_VENV}/bin:${PATH}"
  export ANSIBLE_COLLECTIONS_PATH="${CERT_CTRL_ANSIBLE_VENV}/collections"
  export ANSIBLE_COLLECTIONS_SCAN_SYS_PATH=false
  export ANSIBLE_CONFIG="${ANSIBLE_CONFIG:-${CERT_CTRL_ANSIBLE_DIR}/ansible.cfg}"
}

cert_ctrl_require_ansible() {
  cert_ctrl_ansible_paths
  if [[ ! -x "${CERT_CTRL_ANSIBLE_VENV}/bin/ansible-playbook" \
    || ! -f "${CERT_CTRL_ANSIBLE_VENV}/.cert-ctrl-ready" ]] \
    || ! cmp -s "${CERT_CTRL_ANSIBLE_DIR}/requirements.txt" "${CERT_CTRL_ANSIBLE_VENV}/.requirements.txt" \
    || ! cmp -s "${CERT_CTRL_ANSIBLE_DIR}/requirements.yml" "${CERT_CTRL_ANSIBLE_VENV}/.requirements.yml"; then
    echo "Project Ansible environment is missing, incomplete, or its dependency pins changed." >&2
    printf 'Run: bash "%s"\n' "${CERT_CTRL_ANSIBLE_SETUP}" >&2
    return 1
  fi
  cert_ctrl_ansible_exports
  CERT_CTRL_ANSIBLE_PLAYBOOK="${CERT_CTRL_ANSIBLE_VENV}/bin/ansible-playbook"
}
