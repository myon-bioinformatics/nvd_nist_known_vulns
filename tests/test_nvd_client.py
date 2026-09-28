import importlib.util, io, json, tempfile, unittest
from pathlib import Path
from unittest import mock
ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("nvd_client",ROOT/"nvd_nist_known_vulns.py")
nvd=importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(nvd)

class Tests(unittest.TestCase):
    def test_format_handles_optional_fields_and_cvss30(self):
        p={"vulnerabilities":[{"cve":{"id":"CVE-T-1","descriptions":[{"lang":"en","value":"x"}],"metrics":{"cvssMetricV30":[{"cvssData":{"version":"3.0","baseScore":7.5,"vectorString":"CVSS:3.0/AV:N"}}]}}},{"cve":{"id":"CVE-T-2","metrics":{}}}]}
        r=nvd.format_cve_data(p)
        self.assertEqual(r["CVE-T-1"]["cvss_v3"]["base_score"],7.5)
        self.assertIsNone(r["CVE-T-2"]["description"]); self.assertEqual(r["CVE-T-2"]["cwe"],[])
    def test_pagination(self):
        pages=[{"totalResults":3,"vulnerabilities":[{"cve":{"id":"A"}},{"cve":{"id":"B"}}]},{"totalResults":3,"vulnerabilities":[{"cve":{"id":"C"}}]}]
        with mock.patch.object(nvd,"api_call",side_effect=pages) as call: self.assertEqual(len(list(nvd.iter_cve_pages("cpe"))),2)
        self.assertEqual(call.call_args_list[1].kwargs["start_index"],2)
    def test_ini(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/"x.ini"; p.write_text("[cpeName]\ncpe1=cpe:test\n",encoding="utf-8")
            self.assertEqual(nvd.read_ini(str(p)),["cpe:test"])
    def test_api_key_is_header_not_query(self):
        response=io.BytesIO(b'{"totalResults":0,"vulnerabilities":[]}')
        response.__enter__=lambda s:s; response.__exit__=lambda *a:None
        with mock.patch.object(nvd,"urlopen",return_value=response) as opened:
            nvd.api_call("cpe:test",api_key="secret")
        request=opened.call_args.args[0]
        self.assertEqual(request.get_header("Apikey"),"secret")
        self.assertNotIn("secret",request.full_url)
if __name__=="__main__": unittest.main()
