"""Keep the legacy stdlib lane on an available Python binary platform."""
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_only_linux_python39_uses_ubuntu_2404():
    import yaml

    workflow = yaml.load(
        (ROOT / '.github/workflows/runtime-compatibility.yml').read_text(encoding='utf-8'),
        Loader=yaml.BaseLoader,
    )
    runtime = workflow['jobs']['runtime']
    assert runtime['runs-on'] == "${{ matrix.os == 'ubuntu-latest' && matrix.python == '3.9' && 'ubuntu-24.04' || matrix.os }}"
    assert runtime['strategy']['matrix'] == {
        'os': ['ubuntu-latest'],
        'python': ['3.9', '3.10', '3.11', '3.12', '3.13', '3.14'],
        'include': [
            {'os': 'windows-latest', 'python': '3.9'},
            {'os': 'windows-latest', 'python': '3.14'},
            {'os': 'macos-15-intel', 'python': '3.9'},
            {'os': 'macos-latest', 'python': '3.14'},
        ],
    }
    assert workflow['permissions'] == {'contents': 'read'}
    assert runtime['steps'][-1]['run'] == 'python -S -m unittest discover -s tests -p test_nvd_client.py -v'
    assert 'continue-on-error' not in runtime
    assert workflow['jobs']['portability']['runs-on'] == '${{ matrix.os }}'
