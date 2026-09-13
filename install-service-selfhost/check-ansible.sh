#!/usr/bin/env bash
# No remote connections: parse playbooks and run controller-only assertions.
set -euo pipefail
service_root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${service_root}/scripts/ansible-env.sh"
cert_ctrl_require_ansible
"${CERT_CTRL_ANSIBLE_VENV}/bin/python" "${service_root}/scripts/test_freebsd_prerequisites.py"
for playbook in "${CERT_CTRL_ANSIBLE_DIR}"/playbooks/*.yml; do
  "${CERT_CTRL_ANSIBLE_PLAYBOOK}" --syntax-check \
    -i "${CERT_CTRL_ANSIBLE_DIR}/inventory.yml" "${playbook}"
done
for module in ansible.posix.synchronize ansible.windows.win_shell community.general.pkgng; do
  "${CERT_CTRL_ANSIBLE_VENV}/bin/ansible-doc" --type module "${module}" >/dev/null
done
"${CERT_CTRL_ANSIBLE_PLAYBOOK}" -i localhost, \
  "${CERT_CTRL_ANSIBLE_DIR}/tests/controller_smoke.yml"
