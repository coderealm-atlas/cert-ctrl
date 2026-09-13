#!/usr/bin/env python3
"""Regression tests using a disposable checkout and fake Ansible; no deployment."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


SERVICE = Path(__file__).resolve().parents[1]


class AnsibleEnvironmentTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ansible env test ")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.service = self.root / "install-service-selfhost"
        for relative in (
            "deploy.sh", "publish.sh", "ansible.sh", "setup-ansible.sh",
            "scripts/ansible-env.sh", "ansible/requirements.txt",
            "ansible/requirements.yml", "ansible/ansible.cfg",
        ):
            target = self.service / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(SERVICE / relative, target)
        self.venv = self.root / ".venv-ansible"
        self.log = self.root / "invocations.jsonl"
        self.env = dict(os.environ, TEST_ANSIBLE_LOG=str(self.log))
        self.env.pop("ANSIBLE_CONFIG", None)
        # A system tool must never be selected, including when setup is absent.
        system_bin = self.root / "system-bin"
        system_bin.mkdir()
        sentinel = system_bin / "ansible-playbook"
        sentinel.write_text("#!/bin/sh\necho SYSTEM_ANSIBLE_USED >&2\nexit 99\n")
        sentinel.chmod(0o755)
        self.env["PATH"] = str(system_bin) + os.pathsep + self.env["PATH"]

    def ready(self):
        (self.venv / "bin").mkdir(parents=True, exist_ok=True)
        stub = self.venv / "bin/ansible-playbook"
        stub.write_text(f"#!{sys.executable}\n" + """import json, os, sys
with open(os.environ['TEST_ANSIBLE_LOG'], 'a') as stream:
    stream.write(json.dumps({'argv': sys.argv, 'collections': os.environ.get('ANSIBLE_COLLECTIONS_PATH'),
        'scan': os.environ.get('ANSIBLE_COLLECTIONS_SCAN_SYS_PATH'),
        'config': os.environ.get('ANSIBLE_CONFIG'), 'pythonpath': os.environ.get('PYTHONPATH')}) + '\\n')
sys.exit(int(os.environ.get('TEST_ANSIBLE_EXIT', '0')))
""")
        stub.chmod(0o755)
        for name in ("requirements.txt", "requirements.yml"):
            shutil.copy2(self.service / "ansible" / name, self.venv / ("." + name))
        (self.venv / ".cert-ctrl-ready").touch()

    def run_script(self, name, *args, **env):
        return subprocess.run(["bash", str(self.service / name), *args], cwd=self.root,
                              env=dict(self.env, **env), text=True, capture_output=True)

    def calls(self):
        return [json.loads(line) for line in self.log.read_text().splitlines()]

    def test_help_does_not_require_setup(self):
        for name in ("deploy.sh", "publish.sh", "ansible.sh", "setup-ansible.sh"):
            with self.subTest(name=name):
                self.assertEqual(self.run_script(name, "--help").returncode, 0)
        self.assertFalse(self.venv.exists())

    def test_missing_environment_never_falls_back_to_system(self):
        for name, args in (("deploy.sh", ("--action", "build")),
                           ("publish.sh", ("--action", "deploy-app")),
                           ("ansible.sh", ("playbook", "--version"))):
            with self.subTest(name=name):
                result = self.run_script(name, *args)
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertIn("setup-ansible.sh", result.stderr)
                self.assertNotIn("SYSTEM_ANSIBLE_USED", result.stderr)
        self.assertFalse(self.log.exists())

    def test_changed_pins_require_setup(self):
        self.ready()
        for name in ("requirements.txt", "requirements.yml"):
            with self.subTest(name=name):
                snapshot = self.venv / ("." + name)
                original = snapshot.read_text()
                snapshot.write_text(original + "# old pins\n")
                result = self.run_script("ansible.sh", "playbook", "--version")
                self.assertEqual(result.returncode, 1)
                snapshot.write_text(original)
        self.assertFalse(self.log.exists())

    def test_incomplete_setup_is_rejected(self):
        self.ready()
        (self.venv / ".cert-ctrl-ready").unlink()
        self.assertEqual(self.run_script("deploy.sh", "--action", "build").returncode, 1)
        self.assertFalse(self.log.exists())

    def test_deploy_uses_local_tool_and_preserves_arguments(self):
        self.ready()
        result = self.run_script("deploy.sh", "--action", "build", "--builds", "macos",
                                 "--inventory", "inventory with spaces.yml",
                                 "--ansible-config", "custom config.cfg",
                                 ANSIBLE_COLLECTIONS_PATH="/unwanted/system/collections",
                                 ANSIBLE_COLLECTIONS_SCAN_SYS_PATH="true", PYTHONPATH="/unwanted/python")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        call, = self.calls()
        self.assertEqual(call["argv"][0], str(self.venv / "bin/ansible-playbook"))
        self.assertIn("inventory with spaces.yml", call["argv"])
        self.assertIn("build_macos", call["argv"])
        self.assertEqual(call["collections"], str(self.venv / "collections"))
        self.assertEqual(call["scan"], "false")
        self.assertEqual(call["config"], "custom config.cfg")
        self.assertIsNone(call["pythonpath"])

    def test_publish_uses_local_tool_for_each_playbook(self):
        self.ready()
        result = self.run_script("publish.sh", "--action", "all", "--limit", "test-host")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(self.calls()), 3)
        for call in self.calls():
            self.assertEqual(call["argv"][0], str(self.venv / "bin/ansible-playbook"))
            self.assertIn("test-host", call["argv"])

    def test_parallel_builds_use_local_tool(self):
        self.ready()
        result = self.run_script("deploy.sh", "--action", "build", "--builds", "macos,windows",
                                 "--parallel-builds", "--release-version", "v1.2.3")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        calls = self.calls()
        self.assertEqual(len(calls), 2)
        self.assertEqual({call["argv"][call["argv"].index("--limit") + 1] for call in calls},
                         {"build_macos", "build_windows"})
        for call in calls:
            self.assertEqual(call["argv"][0], str(self.venv / "bin/ansible-playbook"))

    def test_direct_cli_preserves_arguments_config_and_exit_code(self):
        self.ready()
        result = self.run_script("ansible.sh", "playbook", "--syntax-check", "file with spaces.yml",
                                 ANSIBLE_CONFIG="custom.cfg", TEST_ANSIBLE_EXIT="17")
        self.assertEqual(result.returncode, 17)
        call, = self.calls()
        self.assertEqual(call["argv"][1:], ["--syntax-check", "file with spaces.yml"])
        self.assertEqual(call["config"], "custom.cfg")

    def test_publish_stops_on_ansible_failure(self):
        self.ready()
        result = self.run_script("publish.sh", "--action", "all", TEST_ANSIBLE_EXIT="17")
        self.assertEqual(result.returncode, 17)
        self.assertEqual(len(self.calls()), 1)


if __name__ == "__main__":
    unittest.main()
