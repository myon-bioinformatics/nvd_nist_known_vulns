"""Parsed CI contract; PyYAML is test-only, not used by application/unittest."""
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
VENDOR_TOOL_PIN = "1eda992aa6fa31a902e2c06428e53ab17e8fe3c1"


def test_public_vendor_ci_locked_without_repository_writes():
    import yaml
    ci = yaml.load((ROOT / '.github/workflows/python.yml').read_text(encoding='utf-8'), Loader=yaml.BaseLoader)
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
    assert pins == [VENDOR_TOOL_PIN] * 2
    assert all(re.fullmatch('[0-9a-f]{40}', pin) for pin in pins)
    assert not (ROOT / '.github/workflows/vendor-update.yml').exists()
    assert ci['permissions'] == {'contents': 'read'}
    for steps in (resolve, test):
        assert all(s['with']['persist-credentials'] == 'false' for s in steps if s.get('uses','').startswith('actions/checkout@'))
    text = (ROOT / '.github/workflows/python.yml').read_text(encoding='utf-8')
    assert not any(word in text for word in ('VENDOR_UPDATE_TOKEN', 'VENDOR_UPDATES_ENABLED', 'GH_TOKEN', 'git push', 'git commit', 'gh pr', 'continue-on-error', 'vendor-mode', 'vendor-promotion.json'))
