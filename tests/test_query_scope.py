"""Filtered query receipts must never certify an unfiltered CPE measurement."""
import contextlib
import io
import json
import unittest
from unittest.mock import patch

import nvd_nist_known_vulns as nvd

CPE = 'cpe:2.3:a:example:app:1:*:*:*:*:*:*:*'


class QueryScopeTests(unittest.TestCase):
    def emit(self, flags, records):
        output = io.StringIO()
        with patch.object(nvd, 'read_ini', return_value=[CPE]), patch.object(nvd, 'fetch_cves', return_value=records) as fetch, contextlib.redirect_stdout(output):
            self.assertEqual(nvd.main(['--silent', *flags]), 0)
        return output.getvalue(), fetch.call_args.kwargs

    def test_filtered_zero_is_not_unfiltered_zero(self):
        plain, _ = self.emit([], [])
        filtered, _ = self.emit(['--cvss-v3-severity', 'CRITICAL'], [])
        self.assertNotEqual(plain, filtered)
        self.assertEqual(json.loads(filtered)['kind'], 'filtered_query_complete')
        self.assertEqual(json.loads(filtered)['query']['filters'], {'cvss_v3_severity': 'CRITICAL'})
        self.assertEqual(nvd.select_cpe_records(nvd.parse_jsonl(plain), [CPE])['status'], 'measured')
        self.assertEqual(nvd.select_cpe_records(nvd.parse_jsonl(filtered), [CPE])['status'], 'not_measured')
        # Existing v1 readers ignore these additive kinds, rather than seeing completion.
        self.assertNotIn(json.loads(filtered)['kind'], ('cve', 'query_complete'))

    def test_filters_bind_both_records_and_request(self):
        for flags in (['--cvss-v3-severity', 'HIGH'], ['--cvss-v3-metrics', ' av:n/ac:l '], ['--cvss-v3-severity', 'CRITICAL', '--cvss-v3-metrics', 'AV:N']):
            with self.subTest(flags=flags):
                text, request = self.emit(flags, [{'id': 'CVE-2026-0001'}])
                rows = nvd.parse_jsonl(text)
                self.assertEqual({r['kind'] for r in rows}, {'filtered_cve', 'filtered_query_complete'})
                self.assertEqual(rows[0]['query'], rows[1]['query'])
                filters = rows[0]['query']['filters']
                self.assertEqual(filters, {k: request[k] for k in ('cvss_v3_severity', 'cvss_v3_metrics') if request[k] is not None})
                self.assertEqual(nvd.select_cpe_records(rows, [CPE])['status'], 'not_measured')

    def test_mixed_snapshots_do_not_mix_counts_or_ids(self):
        plain, _ = self.emit([], [{'id': 'CVE-2026-0001'}])
        filtered, _ = self.emit(['--cvss-v3-severity', 'CRITICAL'], [{'id': 'CVE-2026-9999'}])
        result = nvd.select_cpe_records(nvd.parse_jsonl(plain + filtered), [CPE])
        self.assertEqual(result['status'], 'measured')
        self.assertEqual(result['cve_ids'], ['CVE-2026-0001'])

    def test_ambiguous_scope_is_rejected_or_not_measured(self):
        original = json.loads(nvd._completion_record(CPE, 0))
        for filters in ({'cvss_v3_severity': 'CRITICAL'}, {}, {'unknown': 'value'}):
            with self.subTest(filters=filters):
                row = dict(original, query={'cpe_name': CPE, 'filters': filters})
                with self.assertRaises(ValueError):
                    nvd.parse_jsonl(json.dumps(row))
                self.assertEqual(nvd.select_cpe_records([row], [CPE])['status'], 'not_measured')
        for query in ({'cpe_name': CPE}, {'cpe_name': CPE, 'filters': {'cvss_v3_severity': None}}, {'cpe_name': CPE, 'filters': {'cvss_v3_severity': 'critical'}}):
            with self.subTest(query=query), self.assertRaises(ValueError):
                nvd.parse_jsonl(json.dumps(dict(original, kind='filtered_query_complete', query=query)))

    def test_invalid_empty_filter_does_not_emit_completion(self):
        output = io.StringIO()
        with patch.object(nvd, 'fetch_cves') as fetch, contextlib.redirect_stdout(output), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(nvd.main(['--cvss-v3-metrics', '  ']), 1)
        fetch.assert_not_called()
        self.assertEqual(output.getvalue(), '')
