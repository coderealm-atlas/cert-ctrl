#!/usr/bin/env python3
"""Exercise the macOS build wrapper with fake tools; no network or deployment."""

import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("build-macos-release.sh")


class MacosBootstrapTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="macos build test ")
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name)
        self.vcpkg = self.repo / "external/vcpkg"
        (self.vcpkg / "scripts").mkdir(parents=True)
        self.payload = b"#!/bin/sh\necho current-vcpkg\n"
        (self.vcpkg / "tool-payload").write_bytes(self.payload)
        self.metadata = self.vcpkg / "scripts/vcpkg-tool-metadata.txt"
        self.metadata.write_text(
            "VCPKG_MACOS_SHA=" + hashlib.sha512(self.payload).hexdigest() + "\n"
        )
        self.bootstrap = self.vcpkg / "bootstrap-vcpkg.sh"
        self.bootstrap.write_text("""#!/bin/sh
set -eu
printf 'bootstrap %s\n' "$*" >> "$TEST_EVENTS"
test "$HTTPS_PROXY" = 'http://proxy.example:7890'
if [ "${TEST_BOOTSTRAP_FAIL:-0}" = 1 ]; then exit 7; fi
if [ "${TEST_BOOTSTRAP_NOOP:-0}" = 1 ]; then exit 0; fi
cp external/vcpkg/tool-payload external/vcpkg/vcpkg
chmod +x external/vcpkg/vcpkg
""")
        self.bootstrap.chmod(0o755)
        cmake = self.repo / "fake-cmake"
        cmake.write_text("""#!/bin/sh
set -eu
printf 'cmake %s\n' "$*" >> "$TEST_EVENTS"
mkdir -p build/macos-release install/selfhost-macos/bin
touch install/selfhost-macos/bin/cert_ctrl
""")
        cmake.chmod(0o755)
        self.events = self.repo / "events"
        self.env = dict(os.environ, INSTALL_SERVICE_REPO_PATH=str(self.repo),
                        CMAKE_BIN=str(cmake), TEST_EVENTS=str(self.events),
                        INSTALL_SERVICE_FORCE_BUILD="0",
                        INSTALL_SERVICE_RECONFIG_CMAKE="0", BUILD_TARGET="cert_ctrl",
                        HTTPS_PROXY="http://proxy.example:7890",
                        TEST_BOOTSTRAP_FAIL="0", TEST_BOOTSTRAP_NOOP="0")
        # Only tracked changes matter to the wrapper's existing fast path.
        subprocess.run(["git", "init", "-q", str(self.repo)], check=True)
        subprocess.run(["git", "-c", "user.name=Test", "-c", "user.email=test@example.com",
                        "-c", "commit.gpgsign=false", "commit", "--allow-empty",
                        "-qm", "fixture"], cwd=self.repo, check=True)

    def run_build(self, **env):
        return subprocess.run(["bash", str(SCRIPT)], cwd=self.repo,
                              env=dict(self.env, **env), text=True, capture_output=True)

    def log(self):
        return self.events.read_text().splitlines() if self.events.exists() else []

    def assert_build_passed(self, result):
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue((self.repo / "build/macos-release/.install-service-build.stamp").exists())

    def test_missing_tool_bootstraps_before_configure_build_install(self):
        self.assert_build_passed(self.run_build())
        log = self.log()
        self.assertEqual(len(log), 4)
        self.assertEqual(log[0], "bootstrap -disableMetrics")
        self.assertTrue(log[1].startswith("cmake --preset macos-release"))
        self.assertTrue(log[2].startswith("cmake --build"))
        self.assertTrue(log[3].startswith("cmake --install"))

    def test_stale_executable_is_replaced(self):
        tool = self.vcpkg / "vcpkg"
        tool.write_text("#!/bin/sh\necho old-vcpkg\n")
        tool.chmod(0o755)
        self.assert_build_passed(self.run_build())
        self.assertEqual(tool.read_bytes(), self.payload)
        self.assertEqual(self.log()[0], "bootstrap -disableMetrics")

    def test_matching_tool_does_not_download(self):
        tool = self.vcpkg / "vcpkg"
        tool.write_bytes(self.payload)
        tool.chmod(0o755)
        self.assert_build_passed(self.run_build())
        self.assertEqual(len(self.log()), 3)
        self.assertTrue(all(line.startswith("cmake ") for line in self.log()))

    def test_bootstrap_failure_stops_before_cmake(self):
        result = self.run_build(TEST_BOOTSTRAP_FAIL="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("bootstrap failed", result.stderr)
        self.assertEqual(self.log(), ["bootstrap -disableMetrics"])
        self.assertFalse((self.repo / "build/macos-release/.install-service-build.stamp").exists())

    def test_successful_bootstrap_must_produce_matching_tool(self):
        result = self.run_build(TEST_BOOTSTRAP_NOOP="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("still does not match", result.stderr)
        self.assertEqual(self.log(), ["bootstrap -disableMetrics"])

    def test_missing_bootstrap_stops_before_cmake(self):
        self.bootstrap.unlink()
        result = self.run_build()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("bootstrap files missing", result.stderr)
        self.assertEqual(self.log(), [])

    def test_invalid_metadata_stops_before_cmake(self):
        self.metadata.write_text("VCPKG_MACOS_SHA=invalid\n")
        result = self.run_build()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Invalid or missing VCPKG_MACOS_SHA", result.stderr)
        self.assertEqual(self.log(), [])

    def test_unchanged_build_skips_but_reconfigure_checks_tool(self):
        self.assert_build_passed(self.run_build())
        initial_log = self.log()
        (self.vcpkg / "vcpkg").unlink()
        result = self.run_build()
        self.assert_build_passed(result)
        self.assertIn("No source changes detected", result.stdout)
        self.assertEqual(self.log(), initial_log)
        self.assert_build_passed(self.run_build(INSTALL_SERVICE_RECONFIG_CMAKE="1"))
        self.assertEqual(self.log()[len(initial_log)], "bootstrap -disableMetrics")


if __name__ == "__main__":
    unittest.main()
