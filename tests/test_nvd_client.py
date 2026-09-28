import importlib.util
import io
import json
import tempfile
import unittest
from email.message import Message
from pathlib import Path
from unittest import mock
from urllib.error import HTTPError

ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("nvd_client",ROOT/"nvd_nist_known_vulns.py")
nvd=importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(nvd)

def response(payload):
    raw=io.BytesIO(json.dumps(payload).encode())
    raw.__enter__=lambda s:s; raw.__exit__=lambda *a:None
    return raw

class Tests(unittest.TestCase):
    def setUp(self): nvd._last_request_at=None

    def test_format_handles_optional_fields_and_cvss30(self):
        p={"vulnerabilities":[{"cve":{"id":"CVE-T-1","descriptions":[{"lang":"en","value":"x"}],"metrics":{"cvssMetricV30":[{"cvssData":{"version":"3.0","baseScore":7.5}}]}}},{"cve":{"id":"CVE-T-2","metrics":{}}}]}
        r=nvd.format_cve_data(p); self.assertEqual(r["CVE-T-1"]["cvss_v3"]["base_score"],7.5); self.assertIsNone(r["CVE-T-2"]["description"])

    def test_primary_metric_wins_and_metadata_is_kept(self):
        p={"vulnerabilities":[{"cve":{"id":"CVE-T-3","metrics":{"cvssMetricV31":[
            {"source":"cna","type":"Secondary","cvssData":{"baseScore":5.3}},
            {"source":"nvd@nist.gov","type":"Primary","cvssData":{"baseScore":9.8}}]}}}]}
        m=nvd.format_cve_data(p)["CVE-T-3"]["cvss_v3"]
        self.assertEqual((m["base_score"],m["source"],m["type"]),(9.8,"nvd@nist.gov","Primary"))

    def test_pagination_and_zero_page(self):
        pages=[{"totalResults":3,"vulnerabilities":[{"cve":{"id":"A"}},{"cve":{"id":"B"}}]},{"totalResults":3,"vulnerabilities":[{"cve":{"id":"C"}}]}]
        with mock.patch.object(nvd,"api_call",side_effect=pages) as call: self.assertEqual(len(list(nvd.iter_cve_pages("cpe"))),2)
        self.assertEqual(call.call_args_list[1].kwargs["start_index"],2)
        with mock.patch.object(nvd,"api_call",return_value={"totalResults":0,"vulnerabilities":[]}): self.assertEqual(len(list(nvd.iter_cve_pages("cpe"))),1)

    def test_fetch_deduplicates_and_sorts(self):
        pages=[{"vulnerabilities":[{"cve":{"id":"CVE-Z"}},{"cve":{"id":"CVE-A"}}]},{"vulnerabilities":[{"cve":{"id":"CVE-A"}}]}]
        with mock.patch.object(nvd,"iter_cve_pages",return_value=pages):
            self.assertEqual([x["id"] for x in nvd.fetch_cves("cpe")],["CVE-A","CVE-Z"])

    def test_ini(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/"x.ini"; p.write_text("[cpeName]\ncpe1=cpe:test\n",encoding="utf-8")
            self.assertEqual(nvd.read_ini(str(p)),["cpe:test"])

    def test_api_key_header_and_throttle(self):
        with mock.patch.object(nvd,"urlopen",return_value=response({"vulnerabilities":[]})) as opened, mock.patch.object(nvd.time,"monotonic",side_effect=[10.0,10.0,10.0,10.6]), mock.patch.object(nvd.time,"sleep") as sleep:
            nvd.api_call("one",api_key="secret"); nvd.api_call("two",api_key="secret")
        self.assertEqual(opened.call_args.args[0].get_header("Apikey"),"secret"); self.assertNotIn("secret",opened.call_args.args[0].full_url)
        sleep.assert_called_with(mock.ANY)

    def test_403_and_5xx_retry(self):
        for code in (403,500,502,503,504):
            headers=Message()
            error=HTTPError("u",code,"x",headers,None)
            nvd._last_request_at=None
            with mock.patch.object(nvd,"urlopen",side_effect=[error,response({"ok":True})]) as opened, mock.patch.object(nvd.time,"sleep"), mock.patch.object(nvd.time,"monotonic",return_value=1.0):
                self.assertTrue(nvd._request_json("u")["ok"]); self.assertEqual(opened.call_count,2)

    def test_retry_after_http_date_does_not_crash(self):
        headers=Message(); headers["Retry-After"]="Wed, 21 Oct 2015 07:28:00 GMT"
        error=HTTPError("u",429,"limited",headers,None)
        with mock.patch.object(nvd,"urlopen",side_effect=[error,response({"ok":True})]), mock.patch.object(nvd.time,"sleep"), mock.patch.object(nvd.time,"monotonic",return_value=1.0):
            self.assertTrue(nvd._request_json("u")["ok"])

    def test_main_jsonl_and_exit_code(self):
        record={"id":"CVE-T","description":"日本語","cwe":[],"cvss_v4":None,"cvss_v3":None,"cvss_v2":None,"published":None,"last_modified":None,"source_identifier":None}
        with tempfile.TemporaryDirectory() as d:
            cfg=Path(d)/"c.ini"; cfg.write_text("[cpeName]\na=cpe:test\n",encoding="utf-8")
            out=Path(d)/"out.jsonl"
            with mock.patch.object(nvd,"fetch_cves",return_value=[record]):
                self.assertEqual(nvd.main(["--silent","--config",str(cfg),"--output",str(out)]),0)
            parsed=json.loads(out.read_text(encoding="utf-8")); self.assertEqual(parsed["schema"],nvd.SCHEMA_VERSION); self.assertEqual(parsed["query"]["cpe_name"],"cpe:test")
            old=out.read_text(encoding="utf-8")
            with mock.patch.object(nvd,"fetch_cves",side_effect=RuntimeError("boom")):
                self.assertEqual(nvd.main(["--silent","--config",str(cfg),"--output",str(out)]),1)
            self.assertEqual(out.read_text(encoding="utf-8"),old)

if __name__=="__main__": unittest.main()
