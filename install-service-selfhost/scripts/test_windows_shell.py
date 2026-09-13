#!/usr/bin/env python3
"""Offline task regressions; --windows-host adds read-only SSH execution checks.

Only explicitly selected probes are run remotely, never the build role itself.
"""
import argparse
import copy
from pathlib import Path
import subprocess
import tempfile
import unittest
import uuid

from jinja2 import StrictUndefined
from jinja2.nativetypes import NativeEnvironment
import yaml


SERVICE = Path(__file__).resolve().parents[1]
BUILD = SERVICE / "ansible/roles/install_service_build/tasks/main.yml"
PROBES = ("Check repository directory exists (Windows)",
          "Check repository is a git worktree (Windows)")


def walk(value):
    if isinstance(value, list):
        for item in value:
            yield from walk(item)
    elif isinstance(value, dict):
        if "name" in value:
            yield value
        for key in ("tasks", "pre_tasks", "post_tasks", "block", "rescue", "always"):
            yield from walk(value.get(key, []))


def build_tasks():
    return {task["name"]: task for task in walk(yaml.safe_load(BUILD.read_text()))}


class WindowsShellTest(unittest.TestCase):
    def test_all_powershell_launchers_use_windows_module(self):
        count = 0
        for path in (SERVICE / "ansible").rglob("*.yml"):
            for task in walk(yaml.safe_load(path.read_text())):
                raw = task.get("raw", task.get("ansible.builtin.raw", ""))
                self.assertNotIn("install_service_powershell_executable", str(raw), path)
                script = task.get("ansible.windows.win_shell", "")
                if "install_service_powershell_executable" in script:
                    count += 1
                    self.assertTrue(script.startswith('$ErrorActionPreference = "Stop";'))
                    self.assertTrue(script.rstrip().endswith("exit $LASTEXITCODE"))
        self.assertEqual(count, 17)

    def test_probes_distinguish_missing_paths_from_execution_errors(self):
        env = NativeEnvironment(undefined=StrictUndefined)
        for name in PROBES:
            task = build_tasks()[name]
            template = env.from_string("{{ " + task["failed_when"] + " }}")
            for result, failed in (({"rc": 0}, False), ({"rc": 3}, False),
                                   ({"rc": 1}, True), ({"rc": 17}, True), ({}, True)):
                with self.subTest(name=name, result=result):
                    self.assertIs(template.render(**{task["register"]: result}), failed)
            self.assertFalse(task["changed_when"])
            self.assertIn("Test-Path -LiteralPath", task["ansible.windows.win_shell"])
            self.assertIn("else { exit 3 }", task["ansible.windows.win_shell"])

    def test_missing_repository_defaults_to_missing_git_status(self):
        task = build_tasks()["Default git repo status when path missing (Windows)"]
        self.assertEqual(task["set_fact"]["install_service_repo_git_win"]["rc"], 3)

    def test_release_probes_use_powershell_boolean_literals(self):
        for path in (BUILD, SERVICE / "ansible/playbooks/collect_assets.yml"):
            tasks = list(walk(yaml.safe_load(path.read_text())))
            task, = [task for task in tasks
                     if task["name"].startswith("Determine release version")
                     and "Windows" in task["name"]]
            script = task["ansible.windows.win_shell"]
            self.assertIn("if (${{ install_service_force_clean_git_describe", script)


def live_checks(host):
    definitions = build_tasks()
    tasks = [{"name": "Remember the inventory repository path", "set_fact": {
        "windows_smoke_repo_path": "{{ install_service_repo_path }}"}}]
    tasks.extend(copy.deepcopy(definitions[name]) for name in PROBES)
    tasks.append({"name": "Existing worktree must not trigger clone", "assert": {"that": [
        "install_service_repo_stat_win.rc == 0", "install_service_repo_git_win.rc == 0"]}})
    for clean in (False, True):
        probe = copy.deepcopy(definitions["Determine release version (Windows)"])
        probe["vars"] = {"install_service_force_clean_git_describe": clean}
        tasks.extend([probe, {"name": "Release version probe succeeds", "assert": {"that": [
            "install_service_release_version_cmd_win.rc == 0",
            "install_service_release_version_cmd_win.stdout | trim is match('^v[0-9]')"]}}])
    # A unique absent child of the real repository; nothing is created there.
    missing_path = "{{ windows_smoke_repo_path }}\\.ansible-missing-" + uuid.uuid4().hex
    for name in PROBES:
        probe = copy.deepcopy(definitions[name])
        probe.pop("when", None)
        probe["vars"] = {"install_service_repo_path": missing_path}
        tasks.extend([probe, {"name": "Missing path is not an execution error", "assert": {
            "that": [probe["register"] + ".rc == 3", probe["register"] + " is not failed"]}}])
        broken = copy.deepcopy(probe)
        broken["vars"] = {"install_service_powershell_executable":
                          r"C:\__ansible_missing_interpreter__\pwsh.exe"}
        broken["ignore_errors"] = True
        tasks.extend([broken, {"name": "Interpreter error must fail, not trigger cloning", "assert": {
            "that": [broken["register"] + " is failed",
                     "(" + broken["register"] + ".rc | default(-1)) not in [0, 3]"]}}])
    tasks.extend([
        {"name": "Preserve native command failure through both PowerShell layers",
         "ansible.windows.win_shell": '$ErrorActionPreference = "Stop"; '
         '& "{{ install_service_powershell_executable }}" -NoProfile -NonInteractive '
         "-Command 'exit 17'; exit $LASTEXITCODE",
         "register": "native_exit", "changed_when": False, "ignore_errors": True},
        {"name": "Native failure code is retained", "assert": {
            "that": ["native_exit is failed", "native_exit.rc == 17"]}},
    ])
    play = [{"name": "Read-only Windows shell regression checks", "hosts": host,
             "gather_facts": False, "vars": {"install_service_is_windows": True,
             "install_service_release_version": ""}, "tasks": tasks}]
    with tempfile.TemporaryDirectory(prefix="cert-ctrl-windows-smoke-") as directory:
        playbook = Path(directory) / "smoke.yml"
        playbook.write_text(yaml.safe_dump(play, sort_keys=False))
        subprocess.run([str(SERVICE / "ansible.sh"), "playbook", "-i",
                        str(SERVICE / "ansible/inventory.yml"), str(playbook)], check=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--windows-host", help="Opt in to read-only checks, e.g. win-build")
    args = parser.parse_args()
    result = unittest.TextTestRunner(verbosity=2).run(
        unittest.defaultTestLoader.loadTestsFromTestCase(WindowsShellTest))
    if not result.wasSuccessful():
        raise SystemExit(1)
    if args.windows_host:
        live_checks(args.windows_host)
