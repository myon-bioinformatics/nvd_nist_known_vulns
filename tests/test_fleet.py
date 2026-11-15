"""🌐 Repository and CI contracts: vendor lock, parent pins, workflows, vendor evidence, xprobe adapter, Node parity.

Shared checks come from the parent's vendor/fleet_check.py; stdlib unittest, also under pytest.
Plain test functions are collected by pytest only (the locked lane, with PyYAML); unittest runs the classes.
"""
import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import tomllib
import unittest
from pathlib import Path

from vendor import fleet_check as fleet

ROOT = fleet.repo_root(__file__)
PARENT_WORKFLOW_PIN = "9e3da7ae1846e9604ebc24bb5178f7de094a4e77"
# Node sources and the shared checks stay on accepted upstream commits with exact bytes.
ACCEPTED = {
    "vendor/py_launch.cjs": "384f5dd532076062f7833038764e9a62322c387c",
    "vendor/fleet_check.py": "6c29503cf17eda856766ddfdf4d66a5b0965a8b1",
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
    }
    assert workflow['permissions'] == {'contents': 'read'}
    assert runtime['steps'][-1]['run'] == 'python -S -m unittest discover -s tests -p test_nvd_nist_known_vulns.py -v'
    assert 'continue-on-error' not in runtime
    assert workflow['jobs']['portability']['runs-on'] == '${{ matrix.os }}'


# ── vendor evidence staging: the workflow's commands against real locked bytes ────────────────────


class VendorStagingTests(unittest.TestCase):
    def test_workflow_payload_and_fail_closed(self):
        tool = ROOT / '.vendor-sync-tools/vendor_stage.py'
        if not tool.is_file():
            self.skipTest('requires the workflow full-SHA parent checkout')
        commands = []
        for workflow in (ROOT / '.github/workflows').glob('*.yml'):
            text = workflow.read_text(encoding='utf-8')
            for match in re.finditer(r'(?m)^( +)- name: Stage canonical vendor evidence\n', text):
                indent = match[1]
                tail = text[match.end():]
                block = re.split(r'\n' + indent + r'- ', tail, maxsplit=1)[0] + '\n'
                self.assertIn('if: always()', block)
                self.assertNotIn('continue-on-error', block)
                run = re.search(r'(?m)^' + indent + r'  run: >-\n((?:' + indent + r'    [^\n]*\n)+)', block)
                self.assertIsNotNone(run)
                command = ' '.join(line.strip() for line in run[1].splitlines())
                self.assertIn('--kind locked', command)
                self.assertNotIn('--promotion-receipt', command)
                output = shlex.split(command)[shlex.split(command).index('--output') + 1]
                upload = re.split(r'\n' + indent + r'- ', tail, maxsplit=1)[1]
                self.assertIn('path: ' + output, upload.split('retention-days:', 1)[0])
                commands.append(command)
        self.assertTrue(commands)
        for command in commands:
            kind = shlex.split(command)[shlex.split(command).index('--kind') + 1]
            with self.subTest(command=command, kind=kind), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                args = shlex.split(command)
                args[0] = sys.executable
                args[2] = str(tool)
                manifest = args[args.index('--manifest') + 1]
                lock = json.loads((ROOT / manifest).read_text(encoding='utf-8'))
                for entry in lock['files']:
                    dest = root / entry['destination']
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(ROOT / entry['destination'], dest)
                # A newly enrolled member must be included without a workflow edit.
                data = b'extra reviewed fixture\n'
                extra = dict(lock['files'][0], destination='extra/LICENSE',
                             blob_sha=hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest(),
                             sha256=hashlib.sha256(data).hexdigest())
                lock['files'].append(extra)
                (root / 'extra').mkdir()
                (root / 'extra/LICENSE').write_bytes(data)
                (root / manifest).parent.mkdir(parents=True, exist_ok=True)
                (root / manifest).write_text(json.dumps(lock), encoding='utf-8')
                legacy = [args[i + 1] for i, value in enumerate(args) if value == '--legacy-evidence']
                runtime = [args[i + 1] for i, value in enumerate(args) if value == '--runtime-evidence']
                for member in legacy:
                    (root / member).parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(ROOT / member, root / member)
                for member in runtime:
                    (root / member).write_text('{}', encoding='utf-8')
                result = subprocess.run(args, cwd=root, capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                output = root / args[args.index('--output') + 1]
                evidence = json.loads((output / 'vendor-evidence.json').read_text(encoding='utf-8'))
                expected = {manifest, *(e['destination'] for e in lock['files'])}
                self.assertEqual(set(evidence['locked']), expected)
                self.assertEqual(set(evidence['candidate']), expected)
                self.assertEqual(evidence['kind'], kind)
                self.assertEqual(set(evidence['legacy']), set(legacy))
                self.assertEqual(set(evidence['runtime']), set(runtime))
                expected |= set(legacy) | set(runtime)
                self.assertEqual({p.relative_to(output).as_posix() for p in output.rglob('*') if p.is_file()}, expected | {'vendor-evidence.json'})
                for member in expected:
                    self.assertEqual((output / member).read_bytes(), (root / member).read_bytes())
                    self.assertEqual(evidence['sha256'][member], hashlib.sha256((root / member).read_bytes()).hexdigest())
                shutil.rmtree(output)
                (root / lock['files'][0]['destination']).write_bytes(b'corrupt')
                result = subprocess.run(args, cwd=root, capture_output=True, text=True)
                self.assertEqual(result.returncode, 2)
                self.assertFalse(output.exists())


# ── xprobe pytest adapter: pinned provenance and native evidence (pytest lane) ────────────────────


def test_adapter_provenance():
    rows = fleet.check_lock(ROOT)  # schema, full-SHA ref == commit, Git blob and SHA-256 of every row
    xprobe = {where: row for where, row in rows.items() if row['repository'] == 'myon-bioinformatics/xprobe'}
    assert set(xprobe) == {'vendor/xprobe_pytest.py', 'vendor/xprobe-LICENSE'}
    assert len({row['commit'] for row in xprobe.values()}) == 1
    for destination, row in xprobe.items():
        assert row['source'] == ('scripts/xprobe_pytest.py' if destination.endswith('.py') else 'LICENSE')


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
