"""Keep verification and proposal workflows on the same reviewed tool."""
from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]


class VendorWorkflowTests(unittest.TestCase):
    def test_tool_and_reusable_workflow_pins_match(self):
        placement = (ROOT / '.github/workflows/python.yml').read_text()
        proposals = (ROOT / '.github/workflows/vendor-update.yml').read_text()
        checkout = re.findall(r'^          ref: ([0-9a-f]{40})$', placement, re.M)
        workflow = re.findall(r'reusable-vendor-update\.yml@([0-9a-f]{40})', proposals)
        tool = re.findall(r'^      tool-commit: ([0-9a-f]{40})$', proposals, re.M)
        self.assertEqual(len(checkout), 1)
        self.assertEqual(checkout, workflow)
        self.assertEqual(checkout, tool)
        self.assertIn("if: vars.VENDOR_UPDATES_ENABLED == 'true'", proposals)
        self.assertIn('update-token: ${{ secrets.VENDOR_UPDATE_TOKEN }}', proposals)


if __name__ == '__main__':
    unittest.main()
