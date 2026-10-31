"""Keep Python setup effective before CI's stdlib checks (stdlib-only tests)."""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]


def job_text(path, name):
    workflow = (ROOT / path).read_text(encoding="utf-8")
    match = re.search(r"(?ms)^  " + re.escape(name) + r":\n(.*?)(?=^  [A-Za-z0-9_-]+:\n|\Z)", workflow)
    if match is None:
        raise AssertionError("Missing workflow job: " + name)
    return match.group(1)


class TestCIPythonSetup(unittest.TestCase):
    def test_setup_precedes_first_plain_python_command(self):
        job = job_text(".github/workflows/python.yml", "test")
        setup = job.index("uses: astral-sh/setup-uv@")
        command = re.search(r"(?m)^\s+(?:-?\s*run:\s*)?python(?:3)?\s", job)
        self.assertIsNotNone(command)
        self.assertLess(setup, command.start(), "Configure matrix Python before stdlib checks")
        self.assertIn('python-version: "${{ matrix.python-version }}"', job)
        self.assertIn("activate-environment: true", job)


if __name__ == "__main__":
    unittest.main()
