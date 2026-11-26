"""🌐 Repository and CI contracts: vendor lock, parent pins, workflows, vendor evidence, xprobe adapter, Node parity.

Shared checks come from the parent's vendor/fleet_check.py; stdlib unittest, also under pytest.
Plain test functions are collected by pytest only (the locked lane, with PyYAML); unittest runs the classes.
"""
import json
import os
import re
import subprocess
import sys
import tomllib
import unittest

from vendor import fleet_check as fleet

ROOT = fleet.repo_root(__file__)
PARENT_WORKFLOW_PIN = "0361d4d81add261ba15073fc32f2a524d2b7e2de"
XPROBE, GHI = "myon-bioinformatics/xprobe", "myon-bioinformatics/gh_identity"
# Every locked row's origin; a row from these repositories that is not listed here fails.
SOURCES = {
    "vendor/xprobe_pytest.py": (XPROBE, "scripts/xprobe_pytest.py"),
    "vendor/xprobe-LICENSE": (XPROBE, "LICENSE"),
    "vendor/gh_identity.py": (GHI, "gh_identity.py"),
    "vendor/gh_identity-LICENSE": (GHI, "LICENSE"),
    "vendor/myon-bioinformatics-LICENSE": (fleet.PARENT, "LICENSE"),
    "vendor/py_launch.cjs": (fleet.PARENT, "py_launch.cjs"),
    "vendor/fleet_check.py": (fleet.PARENT, "fleet_check.py"),
    "vendor/cli_args.py": ("myon-bioinformatics/cli_args", "cli_args.py"),
    "vendor/cli_args-LICENSE": ("myon-bioinformatics/cli_args", "LICENSE"),
}
# Node sources and the shared checks stay on accepted upstream commits with exact bytes;
# the xprobe adapter and its licence stay on one commit.
ACCEPTED = {
    "vendor/py_launch.cjs": "de63762d8485e4d398a651715d34ebf4a04c23f2",
    "vendor/fleet_check.py": "20de01921e50e9339aa9271b0547a5be7649b3b3",
    "vendor/xprobe_pytest.py": "326acd667e13b21bf53ccc1590af960edf8cbf6c",
    "vendor/xprobe-LICENSE": "326acd667e13b21bf53ccc1590af960edf8cbf6c",
    "vendor/cli_args.py": "5ae22b1a1b808eca93e3c385a8db867fbeb8ee32",
    "vendor/cli_args-LICENSE": "5ae22b1a1b808eca93e3c385a8db867fbeb8ee32",
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
        self.assertEqual(set(fleet.check_lock(ROOT, commits=ACCEPTED, sources=SOURCES)), set(SOURCES))

    def test_parent_workflow_references_use_reviewed_rollout_commit(self):
        self.assertEqual(set(fleet.parent_refs(ROOT)), {PARENT_WORKFLOW_PIN})
        fleet.check_actions(ROOT)  # every other action: full SHA with its version comment

    def test_project_and_lock_declare_python311_without_runtime_dependencies(self):
        self.assertEqual(fleet.python_floor(ROOT)[0], "3.11")  # pyproject == uv.lock, runtime matrix starts there
        project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        self.assertEqual(project["project"]["dependencies"], [])
        self.assertFalse(project["tool"]["uv"]["package"])
        self.assertEqual(project["tool"]["uv"]["dependency-groups"]["dev"]["requires-python"], ">=3.11")

    def test_ci_sets_up_python_and_node_before_tests(self):
        # The guard is run in bash; on Windows a bare "bash" is the WSL launcher, so that lane checks the setup only.
        fleet.workflow_job(ROOT, "test", node_floor=None if os.name == "nt" else 26, setup="astral-sh/setup-uv@",
                           inputs=('python-version: "${{ matrix.python-version }}"', "activate-environment: true"))

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

    def test_vendor_evidence_staging_uses_locked_bytes_and_fails_closed(self):
        if not (ROOT / ".vendor-sync-tools/vendor_stage.py").is_file():
            self.skipTest("requires the workflow full-SHA parent checkout")
        commands = fleet.vendor_staging(ROOT)
        self.assertEqual(len(commands), 2)
        self.assertTrue(all("--kind locked" in command for command in commands), commands)

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


# ── CI workflows (parsed with PyYAML; pytest lane) ────────────────────────────────────────────────


def test_public_vendor_ci_locked_without_repository_writes():
    import yaml
    ci = yaml.load((ROOT / '.github/workflows/ci.yml').read_text(encoding='utf-8'), Loader=yaml.BaseLoader)
    jobs = ci['jobs']
    resolve = jobs['resolve-vendor']['steps']
    test = jobs['test']['steps']
    assert not any(s.get('name') == 'Update public vendor files for this run' for s in resolve)
    assert 'inputs' not in ci.get('on', {}).get('workflow_dispatch', {})
    assert set(jobs['test']['needs']) == {'changes', 'resolve-vendor'}
    assert jobs['resolve-vendor']['needs'] == 'changes'
    assert jobs['test']['if'] == "needs.changes.outputs.product_changed == 'true'"
    assert not any('vendor_sync.py promote' in s.get('run', '') for steps in (resolve, test) for s in steps)
    assert not any('vendor_sync.py update' in s.get('run', '') for steps in (resolve, test) for s in steps)
    download = next(i for i,s in enumerate(test) if s.get('uses', '').startswith('actions/download-artifact@'))
    verify = next(i for i,s in enumerate(test) if s.get('name') == 'Verify resolved vendor snapshot')
    assert test[download]['with']['name'] == 'vendor-snapshot'
    assert download < verify
    assert 'vendor_sync.py check' in test[verify]['run']
    for steps, name in ((resolve, 'Preserve resolved vendor snapshot'), (test, 'Preserve vendor lock used by this run')):
        upload = next(s for s in steps if s.get('name') == name)
        assert upload['if'] == 'always()'
        assert upload['with']['if-no-files-found'] == 'error'
        assert upload['with']['path'].startswith('build/vendor-evidence-')
    pins = [s['with']['ref'] for steps in (resolve, test) for s in steps
            if s.get('with', {}).get('repository') == 'myon-bioinformatics/myon-bioinformatics']
    assert pins == [PARENT_WORKFLOW_PIN] * 2
    assert all(re.fullmatch('[0-9a-f]{40}', pin) for pin in pins)
    assert not (ROOT / '.github/workflows/vendor-update.yml').exists()
    assert ci['permissions'] == {'contents': 'read'}
    for steps in (resolve, test):
        assert all(s['with']['persist-credentials'] == 'false' for s in steps if s.get('uses','').startswith('actions/checkout@'))
    text = (ROOT / '.github/workflows/ci.yml').read_text(encoding='utf-8')
    assert not any(word in text for word in ('VENDOR_UPDATE_TOKEN', 'VENDOR_UPDATES_ENABLED', 'GH_TOKEN', 'git push', 'git commit', 'gh pr', 'continue-on-error', 'vendor-mode', 'vendor-promotion.json'))
    runtime = (ROOT / '.github/workflows/runtime-compatibility.yml').read_text(encoding='utf-8')
    assert 'python -S -m unittest discover -s tests -v' in text
    assert 'python -S -m unittest discover -s tests -p test_nvd_nist_known_vulns.py -v' in runtime
    assert 'uv run --locked pytest' in text
    assert 'uv run --locked pytest' in runtime
    assert 'python -m pytest' not in text
    assert 'python -m pytest' not in runtime
    project = (ROOT / 'pyproject.toml').read_text(encoding='utf-8')
    assert 'pythonpath = ["."]' in project


def test_supported_runtime_versions_keep_existing_os_coverage():
    import yaml

    workflow = yaml.load(
        (ROOT / '.github/workflows/runtime-compatibility.yml').read_text(encoding='utf-8'),
        Loader=yaml.BaseLoader,
    )
    runtime = workflow['jobs']['runtime']
    assert runtime['runs-on'] == '${{ matrix.os }}'
    assert runtime['strategy']['matrix'] == {
        'os': ['ubuntu-latest'],
        'python': ['3.11', '3.12', '3.13', '3.14'],
        'include': [
            {'os': 'windows-latest', 'python': '3.11'},
            {'os': 'windows-latest', 'python': '3.14'},
            {'os': 'macos-15-intel', 'python': '3.11'},
            {'os': 'macos-latest', 'python': '3.14'},
        ],
        'exclude': "${{ github.event_name == 'pull_request' && fromJSON('[%s]') || fromJSON('[]') }}"
        % (
            '{"python":"3.11"},{"python":"3.12"},{"python":"3.13"},'
            '{"os":"windows-latest","python":"3.14"},{"os":"macos-latest","python":"3.14"}'
        ),
    }
    assert workflow['permissions'] == {'contents': 'read'}
    assert runtime['steps'][-1]['run'] == 'python -S -m unittest discover -s tests -p test_nvd_nist_known_vulns.py -v'
    assert 'continue-on-error' not in runtime
    assert workflow['jobs']['portability']['runs-on'] == '${{ matrix.os }}'


# ── xprobe pytest adapter: native evidence (pytest lane; provenance is in SOURCES/ACCEPTED) ────────────────────


def test_native_failure_evidence(tmp_path):
    suite = tmp_path / 'test_sample.py'
    suite.write_text('''import pytest
def test_failure():
    assert False, "private diagnostic"
@pytest.mark.xfail(reason="private reason")
def test_known_gap():
    assert False
@pytest.mark.xfail(strict=True)
def test_unexpected_pass():
    pass
@pytest.fixture
def resource():
    yield
    raise RuntimeError("private teardown")
def test_cleanup(resource):
    pass
''', encoding='utf-8')
    destination = tmp_path / 'events.jsonl'
    env = dict(os.environ, PYTHONPATH=str(ROOT), PYTEST_DISABLE_PLUGIN_AUTOLOAD='1')
    env.pop('PYTEST_ADDOPTS', None)
    result = subprocess.run(
        [sys.executable, '-m', 'pytest', '-c', os.devnull, '-p', 'vendor.xprobe_pytest',
         '--xprobe-jsonl=' + str(destination), '--xprobe-repository=myon-bioinformatics/nvd_nist_known_vulns',
         str(suite)], cwd=tmp_path, env=env, capture_output=True, text=True, timeout=30)
    assert result.returncode == 1, result.stdout + result.stderr
    text = destination.read_text(encoding='utf-8')
    rows = [json.loads(line) for line in text.splitlines()]
    assert rows[0]['value']['schema'] == 'xprobe.pytest.v1'
    assert rows[-1]['value']['exitstatus'] == 1
    assert rows[-1]['value']['complete'] is True
    outcomes = {(r['value'].get('phase'), r['value'].get('outcome')) for r in rows}
    assert {('call', 'failed'), ('call', 'xfail'), ('call', 'xpass_strict'), ('teardown', 'error')} <= outcomes
    assert all(r['context']['commit_sha'] is None for r in rows)
    assert all(r['context']['repository'] == 'myon-bioinformatics/nvd_nist_known_vulns' for r in rows)
    assert 'private' not in text


if __name__ == "__main__":
    unittest.main()


# 🧰 Scripts: 📝 each one describes itself and ⌨️ one that reads sys.argv declares its arguments (argparse /
# cli_args). Read with ast, never run; the portfolio's script catalog reads the same facts.

class ScriptsDescribeThemselves(unittest.TestCase):
    def test_every_script_has_a_description_and_declared_arguments(self):
        fleet.check_scripts(fleet.repo_root(__file__))

    def test_pull_request_ci_stays_quick(self):
        # ⏱ push limited to branches, superseded PR runs cancelled, every job timed (fleet_check.check_ci)
        fleet.check_ci(fleet.repo_root(__file__))

    def test_root_scripts_import_only_the_standard_library(self):
        root = fleet.repo_root(__file__)
        for path in sorted(root.glob("*.py")):
            if path.name != "conftest.py":
                fleet.check_imports(root, path.name)
