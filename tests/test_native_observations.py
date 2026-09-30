"""Downstream integration of the pinned shared pytest adapter."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def test_adapter_provenance():
    provenance = json.loads((ROOT / 'vendor/xprobe_pytest.provenance.json').read_text())
    data = (ROOT / 'vendor/xprobe_pytest.py').read_bytes()
    commit = '326acd667e13b21bf53ccc1590af960edf8cbf6c'
    blob = '70fac53151e97f5f28d23f9961d3837b7a885ea8'
    sha256 = 'c0ea71f9d971bf47a9f5f1794ef8a7f641dd17694ea8e7f29795d326c5229285'
    assert provenance['repository'] == 'myon-bioinformatics/xprobe'
    assert provenance['path'] == 'scripts/xprobe_pytest.py'
    assert provenance['commit'] == commit
    assert provenance['sha256'] == sha256
    assert provenance['blob_sha'] == blob
    assert hashlib.sha256(data).hexdigest() == sha256
    assert hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest() == blob


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
