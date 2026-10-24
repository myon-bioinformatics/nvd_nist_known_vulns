"""nvd_nist_known_vulns.cjs: Node entry parity with nvd_nist_known_vulns.py through the vendored shared py_launch.cjs."""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
TOOL = "nvd_nist_known_vulns"
ENV_VAR = "NVD_NIST_KNOWN_VULNS_PYTHON"
CASES = [{"id": "help", "args": ["--help"], "rc": 0}, {"id": "bogus", "args": ["--bogus"], "rc": 2}, {"id": "missing-config", "args": ["--config", "no-such-config.ini"], "rc": 2}, {"id": "bad-timeout", "args": ["--cpe", "x", "--timeout", "-1"], "rc": 2}]


def _node() -> str | None:
    node = os.environ.get("NODE") or shutil.which("node")
    if not node:
        return None
    try:
        out = subprocess.run([node, "--version"], capture_output=True, text=True, timeout=10).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    match = re.match(r"v(\d+)", out.strip())
    return node if match and int(match.group(1)) >= 24 else None


NODE = _node()
needs_node = unittest.skipIf(NODE is None, "Node 24+ not available (set NODE)")


def _env() -> dict[str, str]:
    env = dict(os.environ)
    env[ENV_VAR] = sys.executable
    env.pop("PY_LAUNCH_ERROR_FORMAT", None)
    return env


def _run(argv: list[str], cwd: Path) -> tuple[int, str, str]:
    p = subprocess.run(argv, cwd=cwd, env=_env(), capture_output=True, text=True,
                       encoding="utf-8", errors="replace", timeout=120)
    return p.returncode, p.stdout, p.stderr


def _parity(root: Path, args: list[str]) -> tuple[tuple[int, str, str], tuple[int, str, str]]:
    via_node = _run([NODE, str(root / f"{TOOL}.cjs"), *args], root)
    via_python = _run([sys.executable, "-S", str(ROOT / f"{TOOL}.py"), *args], root)
    return via_node, via_python


class NodeEntryTests(unittest.TestCase):
    def test_vendored_launcher_matches_lock(self):
        lock = json.loads((ROOT / "vendor.lock.json").read_text(encoding="utf-8"))
        entry = next(f for f in lock["files"] if f["destination"] == "vendor/py_launch.cjs")
        self.assertEqual(entry["repository"], "myon-bioinformatics/myon-bioinformatics")
        self.assertEqual(entry["source"], "py_launch.cjs")
        data = (ROOT / "vendor" / "py_launch.cjs").read_bytes()
        self.assertEqual(hashlib.sha256(data).hexdigest(), entry["sha256"])
        blob = hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()
        self.assertEqual(blob, entry["blob_sha"])

    def test_entry_uses_shared_launcher_only(self):
        text = (ROOT / f"{TOOL}.cjs").read_text(encoding="utf-8")
        self.assertIn('require("./vendor/py_launch.cjs")', text)
        self.assertNotIn("child_process", text)
        self.assertIn(f'"{TOOL}.py"', text)
        pkg = json.loads((ROOT / "package.json").read_text(encoding="utf-8"))
        self.assertEqual(pkg["engines"]["node"], ">=24")

    @needs_node
    def test_node_matches_python(self):
        for case in CASES:
            with self.subTest(case["id"]):
                via_node, via_python = _parity(ROOT, case["args"])
                self.assertEqual(via_python[0], case["rc"])
                self.assertEqual(via_node, via_python)

    @needs_node
    def test_missing_interpreter_is_launcher_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = _env()
            env[ENV_VAR] = str(Path(tmp) / "no-such-python")
            p = subprocess.run([NODE, str(ROOT / f"{TOOL}.cjs"), "--help"], env=env,
                               capture_output=True, text=True, timeout=60)
        self.assertEqual(p.returncode, 2)
        self.assertEqual(p.stdout, "")

    @needs_node
    def test_mutated_entry_breaks_parity(self):
        mutations = [
            (f'"{TOOL}.py"', '"missing_tool.py"'),
            ("main(PY_SCRIPT, PY_LAUNCH);", "main(PY_SCRIPT, { ...PY_LAUNCH, argv: [] });"),
            ("noSite: true", "noSite: true, isolated: true, argv: ['--help']"),
        ]
        text = (ROOT / f"{TOOL}.cjs").read_text(encoding="utf-8")
        for old, new in mutations:
            with self.subTest(old), tempfile.TemporaryDirectory() as tmp:
                tmp_path = Path(tmp)
                (tmp_path / "vendor").mkdir()
                shutil.copy(ROOT / "vendor" / "py_launch.cjs", tmp_path / "vendor" / "py_launch.cjs")
                shutil.copy(ROOT / f"{TOOL}.py", tmp_path / f"{TOOL}.py")
                self.assertIn(old, text)
                (tmp_path / f"{TOOL}.cjs").write_text(text.replace(old, new), encoding="utf-8")
                self.assertTrue(any(_parity(tmp_path, c["args"])[0] != _parity(ROOT, c["args"])[1]
                                    for c in CASES))


if __name__ == "__main__":
    unittest.main()
