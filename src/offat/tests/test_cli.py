import subprocess
import sys
import unittest


class TestCLI(unittest.TestCase):
    def test_help_starts_with_installed_dependencies(self):
        result = subprocess.run(
            [sys.executable, '-m', 'offat', '--help'],
            capture_output=True,
            text=True,
            timeout=30,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('usage: offat', result.stdout)
        self.assertIn('--file', result.stdout)
