from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def test_failed_update_does_not_execute_check(tmp_path):
    import yaml
    ci = yaml.load((ROOT / '.github/workflows/python.yml').read_text(encoding='utf-8'), Loader=yaml.BaseLoader)
    step = next(s for s in ci['jobs']['resolve-vendor']['steps'] if s.get('name') == 'Update public vendor files for this run')
    assert step['shell'] == 'bash'
    command = step['run'].replace(
        'python -S .vendor-sync-tools/vendor_sync.py update --manifest vendor.lock.json',
        'python -c "raise SystemExit(2)"').replace(
        'python -S .vendor-sync-tools/vendor_sync.py check --manifest vendor.lock.json',
        'python -c "from pathlib import Path; Path(\'check-ran\').touch()"')
    result = subprocess.run(['bash', '--noprofile', '--norc', '-e', '-o', 'pipefail', '-c', command], cwd=tmp_path)
    assert result.returncode == 2
    assert not (tmp_path / 'check-ran').exists()
