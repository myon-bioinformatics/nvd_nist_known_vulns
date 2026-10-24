"""nvd_nist_known_vulns.cjs: Node entry parity with nvd_nist_known_vulns.py through the vendored shared py_launch.cjs."""
from __future__ import annotations

import hashlib
import json
import os
import selectors
import signal
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

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
    def test_ci_enables_node_parity_in_test_job(self):
        workflow = (ROOT / ".github/workflows/python.yml").read_text(encoding="utf-8")
        job = workflow.split("\n  test:\n", 1)[1].split("\n  failure-identity:", 1)[0]
        self.assertIn("actions/setup-node@949feb2413d6458794dcd2491c4babbbce0c15c1", job)
        self.assertIn("node-version: '26'", job)
        self.assertIn("Require supported Node in parity CI", job)
        # This repo also has a stdlib/development compatibility workflow;
        # require Node only in the main "test" matrix that provisions Node 26.
        if os.environ.get("GITHUB_ACTIONS") == "true" and os.environ.get("GITHUB_JOB") == "test":
            self.assertIsNotNone(NODE, "Node 24+ must be installed for CI tests")

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


class NodeProbeTests(unittest.TestCase):
    """_node() returns None unless a Node 24+ binary answers --version."""

    def test_ci_job_requires_node_when_marked(self):
        # Covers the GITHUB_ACTIONS + GITHUB_JOB == test branch in test_ci_enables_node_parity_in_test_job.
        suite = NodeEntryTests("test_ci_enables_node_parity_in_test_job")
        with mock.patch.dict(os.environ, {"GITHUB_ACTIONS": "true", "GITHUB_JOB": "test"}), \
                mock.patch(f"{__name__}.NODE", "/usr/bin/node"):
            suite.test_ci_enables_node_parity_in_test_job()
        with mock.patch.dict(os.environ, {"GITHUB_ACTIONS": "true", "GITHUB_JOB": "test"}), \
                mock.patch(f"{__name__}.NODE", None):
            with self.assertRaises(AssertionError):
                suite.test_ci_enables_node_parity_in_test_job()

    def test_no_node_anywhere(self):
        with mock.patch.dict(os.environ, {"NODE": ""}), mock.patch.object(shutil, "which", return_value=None):
            self.assertIsNone(_node())

    def test_unrunnable_node(self):
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.dict(os.environ, {"NODE": str(Path(tmp) / "no-such-node")}):
                self.assertIsNone(_node())

    def test_version_gate(self):
        for out, ok in (("v20.19.2\n", False), ("v23.9.0\n", False), ("v24.0.0\n", True), ("v100.1.0\n", True), ("garbage\n", False)):
            with self.subTest(out), mock.patch.dict(os.environ, {"NODE": "fake-node"}), \
                    mock.patch.object(subprocess, "run", return_value=subprocess.CompletedProcess([], 0, out, "")):
                self.assertEqual(_node(), "fake-node" if ok else None)


class LauncherRegressionTests(unittest.TestCase):
    """Real Node/Python regressions for the adopted shared launcher."""

    def setUp(self):
        self.node = NODE
        if self.node is None:
            self.skipTest("Node 24+ is required for launcher regressions")
        self.root = Path(__file__).resolve().parents[1]
        self.tool = TOOL
        self.env = dict(os.environ)
        self.env[ENV_VAR] = sys.executable
        self.env.pop("PY_LAUNCH_ERROR_FORMAT", None)

    @unittest.skipIf(os.name == "nt", "POSIX signal forwarding contract")
    def test_entry_forwards_repeated_signals_text(self):
        self._check_repeated_signals(json_errors=False)

    @unittest.skipIf(os.name == "nt", "POSIX signal forwarding contract")
    def test_entry_forwards_repeated_signals_json(self):
        self._check_repeated_signals(json_errors=True)

    def _check_repeated_signals(self, *, json_errors):
        # Wait for each acknowledgement before sending the next signal, so
        # repeated SIGINT cannot coalesce and no timing sleeps are needed.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "vendor").mkdir()
            shutil.copyfile(self.root / "vendor/py_launch.cjs", root / "vendor/py_launch.cjs")
            shutil.copyfile(self.root / f"{self.tool}.cjs", root / f"{self.tool}.cjs")
            (root / f"{self.tool}.py").write_text(
                "import signal, time\n"
                "signal.signal(signal.SIGINT, lambda *_: print('ACK', flush=True))\n"
                "print('READY', flush=True)\n"
                "while True: time.sleep(60)\n",
                encoding="utf-8",
            )
            env = dict(self.env, PY_LAUNCH_ERROR_FORMAT="json" if json_errors else "")
            child = subprocess.Popen(
                [self.node, str(root / f"{self.tool}.cjs")], env=env,
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, start_new_session=True,
            )
            try:
                with selectors.DefaultSelector() as selector:
                    selector.register(child.stdout, selectors.EVENT_READ)
                    for expected, next_signal in [
                        (b"READY\n", signal.SIGINT),
                        (b"ACK\n", signal.SIGINT),
                        (b"ACK\n", signal.SIGTERM),
                    ]:
                        self.assertTrue(selector.select(timeout=10), "child did not acknowledge forwarded signal")
                        self.assertEqual(child.stdout.readline(), expected)
                        child.send_signal(next_signal)
                stdout, stderr = child.communicate(timeout=10)
                self.assertEqual(child.returncode, 2)
                self.assertEqual(stdout, b"")
                if json_errors:
                    error = json.loads(stderr)
                    self.assertEqual(error["code"], "ESIGNAL")
                    self.assertEqual(error["exit_code"], 2)
                    self.assertIn("SIGTERM", error["message"])
                else:
                    self.assertIn(b"terminated by signal SIGTERM", stderr)
            finally:
                try:
                    os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                child.communicate(timeout=10)

    def test_entry_no_site_also_protects_interpreter_probe(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            marker = root / "site-hook-ran"
            (root / "sitecustomize.py").write_text(
                f"from pathlib import Path\nPath({str(marker)!r}).touch()\n", encoding="utf-8",
            )
            result = subprocess.run(
                [self.node, str(self.root / f"{self.tool}.cjs"), "--help"],
                env=dict(self.env, PYTHONPATH=str(root)), capture_output=True, timeout=30,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(marker.exists(), "noSite must cover interpreter discovery too")

    def test_discovery_honors_no_site_and_isolated_independently(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            marker = root / "site-hook-ran"
            (root / "sitecustomize.py").write_text(
                f"from pathlib import Path\nPath({str(marker)!r}).touch()\n", encoding="utf-8",
            )
            launcher = json.dumps(str(self.root / "vendor/py_launch.cjs"))
            for no_site, isolated in [(False, False), (True, False), (False, True), (True, True)]:
                with self.subTest(no_site=no_site, isolated=isolated):
                    marker.unlink(missing_ok=True)
                    options = json.dumps({"python": sys.executable, "noSite": no_site, "isolated": isolated})
                    # Resolution alone must suppress the hook; testing only the
                    # final Python child would miss the vulnerable version probe.
                    result = subprocess.run(
                        [self.node, "-e", f"require({launcher}).resolvePython({options});"],
                        env=dict(self.env, PYTHONPATH=str(root)), capture_output=True, timeout=30,
                    )
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(marker.exists(), not (no_site or isolated))


if __name__ == "__main__":
    unittest.main()
