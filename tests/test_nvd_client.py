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

    def test_incomplete_or_invalid_pagination_never_completes(self):
        cases = [
            [
                {"totalResults": 3, "vulnerabilities": [{"cve": {"id": "A"}}, {"cve": {"id": "B"}}]},
                {"totalResults": 3, "vulnerabilities": []},
            ],
            [{"vulnerabilities": [{"cve": {"id": "A"}}]}],
            [
                {"totalResults": 4, "vulnerabilities": [{"cve": {"id": "A"}}, {"cve": {"id": "B"}}]},
                {"totalResults": 2, "vulnerabilities": []},
            ],
        ]
        for pages in cases:
            with self.subTest(pages=pages), mock.patch.object(nvd, "api_call", side_effect=pages):
                with self.assertRaises(RuntimeError):
                    list(nvd.iter_cve_pages("cpe"))

    def test_failed_cpe_does_not_emit_completion(self):
        with tempfile.TemporaryDirectory() as d:
            cfg=Path(d)/"c.ini"; cfg.write_text("[cpeName]\na=cpe:ok\nb=cpe:failed\n",encoding="utf-8")
            ok={"id":"CVE-T","description":None,"cwe":[],"cvss_v4":None,"cvss_v3":None,"cvss_v2":None,"published":None,"last_modified":None,"source_identifier":None}
            stdout=io.StringIO()
            with mock.patch.object(nvd,"fetch_cves",side_effect=[[ok],RuntimeError("boom")]), mock.patch("sys.stdout",stdout):
                self.assertEqual(nvd.main(["--silent","--config",str(cfg)]),1)
            rows=[json.loads(line) for line in stdout.getvalue().split("\n") if line]
            self.assertEqual([row["kind"] for row in rows],["cve","query_complete"])
            self.assertEqual(rows[-1]["query"]["cpe_name"],"cpe:ok")
            self.assertFalse(any(row.get("query",{}).get("cpe_name")=="cpe:failed" and row.get("kind")=="query_complete" for row in rows))

    def test_fetch_deduplicates_and_sorts(self):
        pages=[{"vulnerabilities":[{"cve":{"id":"CVE-Z"}},{"cve":{"id":"CVE-A"}}]},{"vulnerabilities":[{"cve":{"id":"CVE-A"}}]}]
        with mock.patch.object(nvd,"iter_cve_pages",return_value=pages):
            self.assertEqual([x["id"] for x in nvd.fetch_cves("cpe")],["CVE-A","CVE-Z"])

    def test_jsonl_consumer_completion_and_deduplication(self):
        cpe1="cpe:2.3:a:example:one:1:*:*:*:*:*:*:*"; cpe2="cpe:2.3:a:example:two:1:*:*:*:*:*:*:*"
        rows=[
            {"schema":nvd.SCHEMA_VERSION,"kind":"cve","query":{"cpe_name":cpe1},"id":"CVE-1","description":"left\u2028right"},
            {"schema":nvd.SCHEMA_VERSION,"kind":"cve","query":{"cpe_name":cpe2},"id":"CVE-1"},
            {"schema":nvd.SCHEMA_VERSION,"kind":"query_complete","query":{"cpe_name":cpe1},"cve_count":1},
            {"schema":nvd.SCHEMA_VERSION,"kind":"query_complete","query":{"cpe_name":cpe2},"cve_count":1},
        ]
        text="\n".join(json.dumps(x,ensure_ascii=False) for x in rows)
        parsed=nvd.parse_jsonl(text)
        self.assertEqual(parsed[0]["description"],"left\u2028right")
        result=nvd.select_cpe_records(parsed,[cpe1,cpe2])
        self.assertEqual((result["status"],result["cve_count"],result["cve_ids"]),("measured",1,["CVE-1"]))

    def test_jsonl_consumer_requires_completion_and_matching_count(self):
        cpe="cpe:2.3:a:example:one:1:*:*:*:*:*:*:*"
        cve={"schema":nvd.SCHEMA_VERSION,"kind":"cve","query":{"cpe_name":cpe},"id":"CVE-1"}
        missing=nvd.select_cpe_records([cve],[cpe])
        self.assertEqual(missing["reason"],"missing_query_completion")
        for count in (0,2):
            result=nvd.select_cpe_records([cve,{"schema":nvd.SCHEMA_VERSION,"kind":"query_complete","query":{"cpe_name":cpe},"cve_count":count}],[cpe])
            self.assertEqual(result["reason"],"completion_count_mismatch")

    def test_jsonl_consumer_zero_unknown_kind_bom_and_validation(self):
        cpe="cpe:2.3:a:example:one:1:*:*:*:*:*:*:*"
        future={"schema":nvd.SCHEMA_VERSION,"kind":"future","query":{"cpe_name":cpe},"payload":"x"}
        complete={"schema":nvd.SCHEMA_VERSION,"kind":"query_complete","query":{"cpe_name":cpe},"cve_count":0}
        parsed=nvd.parse_jsonl("\ufeff"+json.dumps(future)+"\n"+json.dumps(complete))
        self.assertEqual(parsed,[complete])
        self.assertEqual(nvd.select_cpe_records(parsed,[cpe])["cve_count"],0)
        bad=[
            {"schema":nvd.SCHEMA_VERSION,"kind":"cve","query":{"cpe_name":cpe},"id":"GHSA-x"},
            {"schema":nvd.SCHEMA_VERSION,"kind":"query_complete","query":{"cpe_name":cpe},"cve_count":True},
        ]
        for row in bad:
            with self.assertRaises(ValueError): nvd.parse_jsonl(json.dumps(row))
        with self.assertRaises(ValueError): nvd.select_cpe_records(parsed,["requests"])

    def test_ini(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/"x.ini"; p.write_text("[cpeName]\ncpe1=cpe:test\n",encoding="utf-8")
            self.assertEqual(nvd.read_ini(str(p)),["cpe:test"])

    def test_api_key_header_and_throttle(self):
        with mock.patch.object(nvd,"urlopen",side_effect=[response({"vulnerabilities":[]}),response({"vulnerabilities":[]})]) as opened, mock.patch.object(nvd.time,"monotonic",side_effect=[10.0,10.0,10.0,10.6]), mock.patch.object(nvd.time,"sleep") as sleep:
            nvd.api_call("one",api_key="secret"); nvd.api_call("two",api_key="secret")
        self.assertEqual(opened.call_args.args[0].get_header("Apikey"),"secret"); self.assertNotIn("secret",opened.call_args.args[0].full_url)
        sleep.assert_called_once_with(0.6)

    def test_403_and_5xx_retry(self):
        for code in (403,500,502,503,504):
            headers=Message()
            error=HTTPError("https://example.invalid",code,"x",headers,None)
            nvd._last_request_at=None
            with mock.patch.object(nvd,"urlopen",side_effect=[error,response({"ok":True})]) as opened, mock.patch.object(nvd.time,"sleep"), mock.patch.object(nvd.time,"monotonic",return_value=1.0):
                self.assertTrue(nvd._request_json("https://example.invalid")["ok"]); self.assertEqual(opened.call_count,2)

    def test_retry_after_http_date_does_not_crash(self):
        headers=Message(); headers["Retry-After"]="Wed, 21 Oct 2015 07:28:00 GMT"
        error=HTTPError("https://example.invalid",429,"limited",headers,None)
        with mock.patch.object(nvd,"urlopen",side_effect=[error,response({"ok":True})]), mock.patch.object(nvd.time,"sleep"), mock.patch.object(nvd.time,"monotonic",return_value=1.0):
            self.assertTrue(nvd._request_json("https://example.invalid")["ok"])

    def test_main_jsonl_and_exit_code(self):
        record={"id":"CVE-T","description":"日本語","cwe":[],"cvss_v4":None,"cvss_v3":None,"cvss_v2":None,"published":None,"last_modified":None,"source_identifier":None}
        with tempfile.TemporaryDirectory() as d:
            cfg=Path(d)/"c.ini"; cfg.write_text("[cpeName]\na=cpe:test\n",encoding="utf-8")
            out=Path(d)/"out.jsonl"
            with mock.patch.object(nvd,"fetch_cves",return_value=[record]):
                self.assertEqual(nvd.main(["--silent","--config",str(cfg),"--output",str(out)]),0)
            lines=[json.loads(line) for line in out.read_text(encoding="utf-8").split("\n") if line]
            self.assertEqual(lines[0]["schema"],nvd.SCHEMA_VERSION); self.assertEqual(lines[0]["query"]["cpe_name"],"cpe:test")
            self.assertEqual(lines[0]["kind"],"cve")
            self.assertEqual(lines[1],{"cve_count":1,"kind":"query_complete","query":{"cpe_name":"cpe:test"},"schema":nvd.SCHEMA_VERSION})
            old=out.read_text(encoding="utf-8")
            with mock.patch.object(nvd,"fetch_cves",side_effect=RuntimeError("boom")):
                self.assertEqual(nvd.main(["--silent","--config",str(cfg),"--output",str(out)]),1)
            self.assertEqual(out.read_text(encoding="utf-8"),old)

    def test_zero_result_still_emits_query_completion(self):
        with tempfile.TemporaryDirectory() as d:
            cfg=Path(d)/"c.ini"; cfg.write_text("[cpeName]\na=cpe:zero\n",encoding="utf-8")
            out=Path(d)/"out.jsonl"
            with mock.patch.object(nvd,"fetch_cves",return_value=[]):
                self.assertEqual(nvd.main(["--silent","--config",str(cfg),"--output",str(out)]),0)
            lines=[json.loads(line) for line in out.read_text(encoding="utf-8").split("\n") if line]
            self.assertEqual(lines,[{"cve_count":0,"kind":"query_complete","query":{"cpe_name":"cpe:zero"},"schema":nvd.SCHEMA_VERSION}])

    def test_throttle_intervals_are_exact(self):
        for api_key, expected in ((None, 6.0), ("secret", 0.6)):
            nvd._last_request_at=10.0
            with mock.patch.object(nvd.time,"monotonic",side_effect=[10.0,10.0+expected]), mock.patch.object(nvd.time,"sleep") as sleep:
                nvd._throttle(api_key)
            sleep.assert_called_once_with(expected)

    def test_authenticated_403_is_not_retried(self):
        headers=Message(); error=HTTPError("https://example.invalid",403,"forbidden",headers,None)
        with mock.patch.object(nvd,"urlopen",side_effect=error) as opened, mock.patch.object(nvd.time,"sleep"), mock.patch.object(nvd.time,"monotonic",return_value=1.0):
            with self.assertRaises(RuntimeError): nvd._request_json("https://example.invalid",api_key="secret")
        self.assertEqual(opened.call_count,1)

    def test_retry_after_is_capped_at_sixty_seconds(self):
        self.assertEqual(nvd._retry_delay("3600",0),60.0)

if __name__=="__main__": unittest.main()
