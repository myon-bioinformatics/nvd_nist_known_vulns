from pathlib import Path
import subprocess
import shutil
import shlex
import sys

ROOT = Path(__file__).resolve().parents[1]


def test_failed_promote_does_not_execute_check(tmp_path):
    import yaml
    ci = yaml.load((ROOT / '.github/workflows/python.yml').read_text(encoding='utf-8'), Loader=yaml.BaseLoader)
    step = next(s for s in ci['jobs']['resolve-vendor']['steps'] if s.get('name') == 'Update public vendor files for this run')
    assert step['shell'] == 'bash'
    interpreter = shlex.quote(Path(sys.executable).as_posix())
    command = step['run'].replace(
        'python -S .vendor-sync-tools/vendor_sync.py promote --manifest vendor.lock.json',
        interpreter + ' -c "raise SystemExit(2)"').replace(
        'python -S .vendor-sync-tools/vendor_sync.py check --manifest vendor.lock.json',
        interpreter + ' -c "from pathlib import Path; Path(\'check-ran\').touch()"')
    bash = 'bash'
    if sys.platform == 'win32':
        # Actions uses Git Bash; PATH's bash.exe can instead be the WSL launcher.
        git = Path(shutil.which('git'))
        bash = next(str(p) for p in (git.parent / 'bash.exe', git.parent.parent / 'bin/bash.exe') if p.is_file())
    result = subprocess.run([bash, '--noprofile', '--norc', '-e', '-o', 'pipefail', '-c', command], cwd=tmp_path)
    assert result.returncode == 2
    assert not (tmp_path / 'check-ran').exists()
