#!/usr/bin/env bash
set -euo pipefail

service_root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${service_root}/scripts/ansible-env.sh"
if [[ $# -gt 0 ]]; then
  echo "Usage: setup-ansible.sh (set ANSIBLE_SETUP_PYTHON to select Python 3.12-3.14)"
  [[ "$1" == "--help" || "$1" == "-h" ]] && exit 0
  exit 2
fi
cert_ctrl_ansible_paths
setup_python="${ANSIBLE_SETUP_PYTHON:-python3}"
"${setup_python}" -c 'import sys; sys.exit(0 if (3, 12) <= sys.version_info[:2] <= (3, 14) else "Ansible requires controller Python 3.12-3.14")'
if [[ ! -f "${CERT_CTRL_ANSIBLE_VENV}/pyvenv.cfg" ]]; then
  if [[ -e "${CERT_CTRL_ANSIBLE_VENV}" ]]; then
    echo "Refusing to overwrite a non-virtualenv directory: ${CERT_CTRL_ANSIBLE_VENV}" >&2
    exit 1
  fi
  "${setup_python}" -m venv "${CERT_CTRL_ANSIBLE_VENV}"
fi
cert_ctrl_ansible_exports
"${CERT_CTRL_ANSIBLE_VENV}/bin/python" -c 'import sys; sys.exit(0 if (3, 12) <= sys.version_info[:2] <= (3, 14) else "Existing virtualenv uses unsupported Python; move it aside and rerun setup")'
# A failed update must never be considered deployable.
rm -f "${CERT_CTRL_ANSIBLE_VENV}/.cert-ctrl-ready"
"${CERT_CTRL_ANSIBLE_VENV}/bin/python" -m pip --disable-pip-version-check install \
  --upgrade -r "${CERT_CTRL_ANSIBLE_DIR}/requirements.txt"
"${CERT_CTRL_ANSIBLE_VENV}/bin/python" -m pip check
"${CERT_CTRL_ANSIBLE_VENV}/bin/ansible-galaxy" collection install \
  -r "${CERT_CTRL_ANSIBLE_DIR}/requirements.yml" -p "${ANSIBLE_COLLECTIONS_PATH}" --force
cp "${CERT_CTRL_ANSIBLE_DIR}/requirements.txt" "${CERT_CTRL_ANSIBLE_VENV}/.requirements.txt"
cp "${CERT_CTRL_ANSIBLE_DIR}/requirements.yml" "${CERT_CTRL_ANSIBLE_VENV}/.requirements.yml"
touch "${CERT_CTRL_ANSIBLE_VENV}/.cert-ctrl-ready"
"${CERT_CTRL_ANSIBLE_VENV}/bin/ansible-playbook" --version
echo "Project Ansible is ready. No activation is needed; system Ansible is unchanged."
