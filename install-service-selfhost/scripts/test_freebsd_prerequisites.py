#!/usr/bin/env python3
"""Check the real prerequisite task without installing packages or using SSH.

Run with .venv-ansible/bin/python (uses its pinned YAML and Jinja libraries).
"""
from pathlib import Path
import unittest

from jinja2 import StrictUndefined
from jinja2.nativetypes import NativeEnvironment
import yaml


SERVICE = Path(__file__).resolve().parents[1]


class FreebsdPrerequisiteTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        plays = yaml.safe_load((SERVICE / "ansible/playbooks/build_release.yml").read_text())
        play, = [play for play in plays if play.get("hosts") == "build_freebsd"]
        cls.task, = [task for task in play["pre_tasks"]
                     if task["name"] == "Install FreeBSD native build prerequisites"]
        cls.jinja = NativeEnvironment(undefined=StrictUndefined)
        cls.jinja.filters["combine"] = lambda left, right: {**left, **right}

    def render(self, field, **variables):
        return self.jinja.from_string(self.task[field]).render(**variables)

    def test_proxy_and_bypass_settings_reach_root_task(self):
        proxy = {"HTTP_PROXY": "http://proxy.example:7890",
                 "HTTPS_PROXY": "http://proxy.example:7890",
                 "NO_PROXY": "localhost,127.0.0.1"}
        env = self.render("environment", install_service_proxy_env=proxy)
        for key, value in proxy.items():
            self.assertEqual(env[key], value)
        self.assertEqual(env["ASSUME_ALWAYS_YES"], "yes")
        self.assertEqual(env["BATCH"], "yes")
        self.assertIs(self.task["become"], True)

    def test_no_proxy_configuration_still_disables_prompts(self):
        self.assertEqual(self.render("environment"),
                         {"ASSUME_ALWAYS_YES": "yes", "BATCH": "yes"})

    def test_noninteractive_flags_cannot_be_overridden_by_proxy_dictionary(self):
        env = self.render("environment", install_service_proxy_env={"ASSUME_ALWAYS_YES": "no"})
        self.assertEqual(env["ASSUME_ALWAYS_YES"], "yes")

    def test_default_timeout_and_polling_wait_for_completion(self):
        self.assertEqual(self.render("async", ansible_check_mode=False), 1200)
        self.assertGreater(self.task["poll"], 0)
        self.assertNotIn("ignore_errors", self.task)
        self.assertNotIn("failed_when", self.task)

    def test_timeout_can_be_configured(self):
        self.assertEqual(self.render("async", ansible_check_mode=False,
                                     install_service_freebsd_pkg_timeout_seconds="1800"), 1800)

    def test_check_mode_does_not_use_async_or_force_real_execution(self):
        self.assertEqual(self.render("async", ansible_check_mode=True), 0)
        self.assertNotIn("check_mode", self.task)

    def test_package_scope_is_unchanged_and_not_a_system_upgrade(self):
        module = self.task["community.general.pkgng"]
        self.assertEqual(module["state"], "present")
        self.assertEqual(set(module["name"]), {
            "autoconf", "autoconf-archive", "automake", "bash", "cmake", "curl",
            "git", "libtool", "ninja", "patchelf", "pkgconf", "python3", "unzip",
        })


if __name__ == "__main__":
    unittest.main()
