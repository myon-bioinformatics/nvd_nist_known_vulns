"""Fleet contracts through the parent's shared checks (vendor/fleet_check.py); stdlib unittest, also under pytest."""
import json
import re
import tomllib
import unittest

from vendor import fleet_check as fleet

ROOT = fleet.repo_root(__file__)
PARENT_WORKFLOW_PIN = "9e3da7ae1846e9604ebc24bb5178f7de094a4e77"
# Node sources and the shared checks stay on accepted upstream commits with exact bytes.
ACCEPTED = {
    "vendor/py_launch.cjs": "384f5dd532076062f7833038764e9a62322c387c",
    "vendor/fleet_check.py": "45ed741f7e1f60179934cee6fa1e16a887f97cb0",
}
TOOL, ENV_VAR = "nvd_nist_known_vulns.py", "NVD_NIST_KNOWN_VULNS_PYTHON"
CASES = {
    "help": (["--help"], 0),
    "bogus": (["--bogus"], 2),
    "missing-config": (["--config", "no-such-config.ini"], 2),
    "bad-timeout": (["--cpe", "x", "--timeout", "-1"], 2),
}
# In CI job "test" (which provisions Node 26) a missing Node fails here instead of skipping.
needs_node = unittest.skipIf(fleet.node() is None, "Node 26+ not available (set NODE)")


class FleetTests(unittest.TestCase):
    def test_vendor_lock_matches_checked_in_bytes_and_accepted_commits(self):
        rows = fleet.check_lock(ROOT, commits=ACCEPTED)
        launcher = rows["vendor/py_launch.cjs"]
        self.assertEqual((launcher["repository"], launcher["source"]), (fleet.PARENT, "py_launch.cjs"))

    def test_parent_workflow_references_use_reviewed_rollout_commit(self):
        self.assertEqual(set(fleet.parent_refs(ROOT)), {PARENT_WORKFLOW_PIN})

    def test_project_and_lock_declare_python311_without_runtime_dependencies(self):
        project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        lock = tomllib.loads((ROOT / "uv.lock").read_text(encoding="utf-8"))
        self.assertEqual(project["project"]["requires-python"], ">=3.11")
        self.assertEqual(lock["requires-python"], project["project"]["requires-python"])
        self.assertEqual(project["project"]["dependencies"], [])
        self.assertFalse(project["tool"]["uv"]["package"])
        self.assertEqual(project["tool"]["uv"]["dependency-groups"]["dev"]["requires-python"], ">=3.11")

    def test_ci_sets_up_python_and_node_before_tests(self):
        job = fleet.workflow_job(ROOT, "test")
        command = re.search(r"(?m)^\s+(?:-?\s*run:\s*)?python(?:3)?\s", job)
        self.assertIsNotNone(command)
        self.assertLess(job.index("uses: astral-sh/setup-uv@"), command.start(), "Configure matrix Python before stdlib checks")
        self.assertIn('python-version: "${{ matrix.python-version }}"', job)
        self.assertIn("activate-environment: true", job)
        self.assertIn("actions/setup-node@949feb2413d6458794dcd2491c4babbbce0c15c1", job)
        self.assertIn("node-version: '26'", job)
        self.assertIn("Require supported Node in parity CI", job)

    def test_benchmark_parity_in_both_interpreter_modes(self):
        reference = "mock.patch.object(g['subprocess'], 'check_output', return_value=open(%r, 'rb').read()).start()\n" % str(ROOT / TOOL)
        wrong = "mock.patch.object(g['nvd'], 'select_cpe_records', return_value=['different']).start()\n"
        for optimized in (False, True):
            for mismatch in (False, True):
                with self.subTest(optimized=optimized, mismatch=mismatch):
                    result = fleet.run_main(ROOT, "scripts/benchmark_cpe_count_index.py",
                                            reference + (wrong if mismatch else ""), optimized=optimized)
                    if mismatch:
                        self.assertEqual(result.returncode, 1, result.stderr)
                        self.assertEqual(result.stdout, "")
                        self.assertIn("result mismatch", result.stderr)
                    else:
                        self.assertEqual(result.returncode, 0, result.stderr)
                        self.assertTrue(result.stdout.startswith("{"), result.stdout)

    def test_no_per_tool_wrapper_and_readme_documents_the_direct_command(self):
        self.assertFalse((ROOT / "nvd_nist_known_vulns.cjs").exists())
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn(f"node vendor/py_launch.cjs --env-var {ENV_VAR} -- {TOOL}", readme)
        pkg = json.loads((ROOT / "package.json").read_text(encoding="utf-8"))
        self.assertEqual(pkg["engines"]["node"], ">=26")

    @needs_node
    def test_node_matches_python(self):
        for case, (args, rc) in CASES.items():
            with self.subTest(case):
                via_node, via_python = fleet.node_parity(ROOT, TOOL, ENV_VAR, *args)
                self.assertEqual(via_python[0], rc)
                self.assertEqual(via_node, via_python)

    @needs_node
    def test_vendored_launcher_keeps_its_contract(self):
        fleet.launcher_contract(ROOT, ENV_VAR)


if __name__ == "__main__":
    unittest.main()
