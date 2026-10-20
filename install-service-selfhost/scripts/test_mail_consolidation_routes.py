#!/usr/bin/env python3
"""Exercise route migration against a temporary config, without running services."""
import contextlib
import io
from pathlib import Path
import runpy
import subprocess
import tempfile
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).with_name('configure-mail-consolidation.py')
BASE = '''frontend https
    bind *:443 ssl crt /existing.pem alpn h2,http/1.1
    use_backend ipinfo_backend if host_ipinfo
'''


class RouteMigrationTest(unittest.TestCase):
    def run_helper(self, config, fail=False):
        def path(value):
            if str(value) == '/etc/haproxy/haproxy.cfg':
                return config
            if str(value) == '/opt/certs':
                return config.parent / 'certs'
            return Path(value)

        with patch('pathlib.Path', side_effect=path), \
                patch('subprocess.run') as run, \
                contextlib.redirect_stdout(io.StringIO()):
            if fail:
                run.side_effect = subprocess.CalledProcessError(1, 'haproxy')
            try:
                runpy.run_path(str(SCRIPT), run_name='__main__')
            except SystemExit as exc:
                self.assertEqual(exc.code, 0)
            return run.call_count

    def test_new_configuration_preserves_legacy_routes_and_is_idempotent(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / 'haproxy.cfg'
            config.write_text(BASE)
            self.assertEqual(self.run_helper(config), 2)
            result = config.read_text()
            for host in ['install.never-lost.app', 'install-selfhost.never-lost.app',
                         'install.lets-script.com', 'install.cjj365.cc']:
                self.assertIn(host, result)
            self.assertIn('bind [::]:443 v6only ssl', result)
            self.assertIn('use_backend ipinfo_backend if host_ipinfo', result)
            self.assertEqual(self.run_helper(config), 0)
            self.assertEqual(config.read_text(), result)

    def test_existing_migrated_block_gets_new_names_without_duplicate_backends(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / 'haproxy.cfg'
            config.write_text(BASE)
            self.run_helper(config)
            text = config.read_text()
            for host in ['install.never-lost.app', 'install-selfhost.never-lost.app']:
                text = text.replace(' ' + host + ':443', '').replace(' ' + host, '')
            config.write_text(text)
            self.assertEqual(self.run_helper(config), 2)
            self.assertIn('install.never-lost.app:443', config.read_text())
            self.assertEqual(config.read_text().count('backend migrated_install_app\n'), 1)

    def test_invalid_configuration_restores_previous_file(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / 'haproxy.cfg'
            config.write_text(BASE)
            with self.assertRaises(subprocess.CalledProcessError):
                self.run_helper(config, fail=True)
            self.assertEqual(config.read_text(), BASE)


if __name__ == '__main__':
    unittest.main()
