"""CI updates public vendor files without token or repository writes."""
from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]


class VendorWorkflowTests(unittest.TestCase):
    def test_public_updates_run_before_tests_without_write_credentials(self):
        ci = (ROOT / '.github/workflows/python.yml').read_text(encoding='utf-8')
        self.assertEqual(len(re.findall(r'^          ref: [0-9a-f]{40}$', ci, re.M)), 1)
        self.assertFalse((ROOT / '.github/workflows/vendor-update.yml').exists())
        self.assertIn('options: [update, locked]', ci)
        self.assertIn('default: update', ci)
        self.assertIn("if: inputs.vendor-mode != 'locked'", ci)
        restore = ci.index('vendor_sync.py materialize')
        update = ci.index('vendor_sync.py update')
        check = ci.index('vendor_sync.py check', update)
        test = ci.index('python -S -m unittest', check)
        self.assertLess(restore, update)
        self.assertLess(update, check)
        self.assertLess(check, test)
        self.assertEqual(ci.count('persist-credentials: false'), 2)
        for forbidden in ('contents: write', 'pull-requests: write',
                          'VENDOR_UPDATE_TOKEN', 'VENDOR_UPDATES_ENABLED',
                          'update-token:', 'GH_TOKEN', 'git push', 'git commit',
                          'gh pr', 'continue-on-error'):
            self.assertNotIn(forbidden, ci)


if __name__ == '__main__':
    unittest.main()
