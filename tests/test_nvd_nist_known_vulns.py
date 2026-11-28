"""🧱 nvd_nist_known_vulns behaviour: offline, stdlib only.

CI's runtime-compatibility lane runs this file with `python -S -m unittest` on every runner OS;
pytest also collects the plain function at the end.

- client and CLI: CVSS, NVD requests and retries, pagination, JSONL consumer, process exit codes
- CPE helpers: suggestions are spelling aids, never product applicability evidence
- query scope: filtered query receipts must never certify an unfiltered CPE measurement
- CPE count index: CVE IDs are grouped once per requested CPE
"""
import importlib.util
import contextlib, difflib, io, json, sys, tempfile, unittest
from email.message import Message
from pathlib import Path
from unittest import mock
from urllib.error import HTTPError
from urllib.parse import parse_qs, urlsplit

import nvd_nist_known_vulns as nvd


def load_vendored(name, relpath):
    """Load a vendored file by path under a repo-unique name (cli_args README: Loading a vendored copy)."""
    if name not in sys.modules:
        spec = importlib.util.spec_from_file_location(name, Path(__file__).resolve().parents[1] / relpath)
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
    return sys.modules[name]


run_cli = load_vendored("nvd_nist_known_vulns_cli_args", "vendor/cli_args.py").run_cli

ROOT = Path(__file__).resolve().parents[1]


# ── client and CLI ────────────────────────────────────────────────────────────────────────────────


def summary(description=None):
    """A normalized CVE record as fetch_cves returns it (all optional fields empty)."""
    return {"id": "CVE-T", "description": description, "cwe": [], "cvss_v4": None, "cvss_v3": None,
            "cvss_v2": None, "published": None, "last_modified": None, "source_identifier": None}


def response(payload):
    raw=io.BytesIO(json.dumps(payload).encode())
    raw.__enter__=lambda s:s; raw.__exit__=lambda *a:None
    return raw


class NvdClientTests(unittest.TestCase):
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

    def test_calculate_cvss_base_v3_known_vectors(self):
        cases = [
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "CRITICAL"),
            ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "CRITICAL"),
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0, "CRITICAL"),
            ("CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", 7.8, "HIGH"),
            ("CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:N", 3.8, "LOW"),
        ]
        for vector, score, severity in cases:
            with self.subTest(vector=vector):
                result = nvd.calculate_cvss_base(vector)
                self.assertEqual(result["base_score"], score)
                self.assertEqual(result["base_severity"], severity)

    def test_calculate_cvss_base_v2_and_rejects_v4(self):
        result = nvd.calculate_cvss_base("AV:N/AC:L/Au:N/C:C/I:C/A:C")
        self.assertEqual((result["version"], result["base_score"], result["base_severity"]), ("2.0", 10.0, "HIGH"))
        with self.assertRaises(ValueError):
            nvd.calculate_cvss_base("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N")

    def test_cvss_vector_separator_regressions(self):
        vectors = (
            "AV:N/AC:L/Au:N/C:C/I:C/A:C",
            "CVSS:2.0/AV:N/AC:L/Au:N/C:C/I:C/A:C",
            "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        )
        for vector in vectors:
            # Exercise every boundary, including the version-prefix boundary.
            malformed = ["/" + vector, vector + "/", vector + "//"]
            malformed.extend(vector[:i] + "/" + vector[i:]
                             for i, char in enumerate(vector) if char == "/")
            for invalid in malformed:
                with self.subTest(vector=invalid):
                    with self.assertRaisesRegex(ValueError, "^malformed CVSS vector: empty segment$"):
                        nvd.calculate_cvss_base(invalid)

    def test_cvss_duplicate_and_missing_metrics_are_distinct(self):
        for version in ("2.0", "3.0", "3.1"):
            metrics = ("AV:N/AC:L/Au:N/C:C/I:C/A:C" if version == "2.0"
                       else "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
            prefix = "CVSS:" + version + "/"
            for metric in metrics.split("/"):
                key = metric.split(":")[0]
                with self.subTest(version=version, key=key):
                    with self.assertRaisesRegex(ValueError, "^duplicate CVSS metric: " + key + "$"):
                        nvd.calculate_cvss_base(prefix + metrics + "/" + metric)
                    remaining = [part for part in metrics.split("/") if part != metric]
                    with self.assertRaisesRegex(ValueError, "missing metrics: " + key + "$"):
                        nvd.calculate_cvss_base(prefix + "/".join(remaining))
            # Conflicting duplicates must not silently replace the first value.
            with self.assertRaisesRegex(ValueError, "^duplicate CVSS metric: AV$"):
                nvd.calculate_cvss_base(prefix + metrics + "/AV:L")

    def test_cvss_valid_vector_compatibility(self):
        v2 = "AV:N/AC:L/Au:N/C:C/I:C/A:C"
        for vector in (v2, "CVSS:2.0/" + v2, v2 + "/E:ND/RL:ND/RC:ND"):
            with self.subTest(vector=vector):
                self.assertEqual(nvd.calculate_cvss_base(vector),
                                 {"version": "2.0", "base_score": 10.0, "base_severity": "HIGH"})
        # FIRST v3 section 6 requires arbitrary metric order and optional metrics.
        for version in ("3.0", "3.1"):
            vector = "CVSS:" + version + "/S:U/AV:N/AC:L/PR:H/UI:N/C:L/I:L/A:N/E:F/RL:X"
            with self.subTest(version=version):
                self.assertEqual(nvd.calculate_cvss_base(vector),
                                 {"version": version, "base_score": 3.8, "base_severity": "LOW"})

    def test_metric_includes_calculated_score_from_vector(self):
        p = {
            "vulnerabilities": [{
                "cve": {
                    "id": "CVE-T-4",
                    "metrics": {
                        "cvssMetricV31": [{
                            "source": "nvd@nist.gov",
                            "type": "Primary",
                            "cvssData": {
                                "version": "3.1",
                                "baseScore": 9.8,
                                "baseSeverity": "CRITICAL",
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                            },
                        }],
                    },
                },
            }],
        }
        m = nvd.format_cve_data(p)["CVE-T-4"]["cvss_v3"]
        self.assertEqual(m["calculated_base_score"], 9.8)
        self.assertEqual(m["calculated_base_severity"], "CRITICAL")

    def test_api_call_includes_cvss_v3_filters(self):
        with mock.patch.object(nvd, "_request_json", return_value={"ok": True}) as request:
            nvd.api_call("cpe:test", cvss_v3_severity="HIGH", cvss_v3_metrics="AV:N/AC:L")
        url = request.call_args.args[0]
        self.assertIn("cpeName=cpe%3Atest", url)
        self.assertIn("cvssV3Severity=HIGH", url)
        self.assertIn("cvssV3Metrics=AV%3AN%2FAC%3AL", url)

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
            ok=summary()
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

    def test_jsonl_consumer_rejects_malformed_boundary_values(self):
        cpe="cpe:2.3:a:example:one:1:*:*:*:*:*:*:*"
        cases=[
            {"schema":nvd.SCHEMA_VERSION,"kind":"query_complete","query":{"cpe_name":cpe},"cve_count":-1},
            {"schema":nvd.SCHEMA_VERSION,"kind":"query_complete","query":{"cpe_name":""},"cve_count":0},
            {"schema":nvd.SCHEMA_VERSION,"kind":"query_complete","query":None,"cve_count":0},
            {"schema":nvd.SCHEMA_VERSION,"kind":"cve","query":{"cpe_name":""},"id":"CVE-1"},
            {"schema":nvd.SCHEMA_VERSION,"kind":"cve","query":None,"id":"CVE-1"},
        ]
        for row in cases:
            with self.subTest(row=row), self.assertRaises(ValueError):
                nvd.parse_jsonl(json.dumps(row))

    def test_jsonl_consumer_rejects_wrong_schema(self):
        cpe="cpe:2.3:a:example:one:1:*:*:*:*:*:*:*"
        row={"schema":"nvd-cve-summary/999","kind":"query_complete","query":{"cpe_name":cpe},"cve_count":0}
        with self.assertRaises(ValueError):
            nvd.parse_jsonl(json.dumps(row))

    def test_jsonl_consumer_rejects_conflicting_completions(self):
        cpe="cpe:2.3:a:example:one:1:*:*:*:*:*:*:*"
        rows=[
            {"schema":nvd.SCHEMA_VERSION,"kind":"query_complete","query":{"cpe_name":cpe},"cve_count":0},
            {"schema":nvd.SCHEMA_VERSION,"kind":"query_complete","query":{"cpe_name":cpe},"cve_count":1},
        ]
        with self.assertRaises(ValueError):
            nvd.select_cpe_records(rows,[cpe])

    def test_read_jsonl_accepts_utf8_bom(self):
        cpe="cpe:2.3:a:example:one:1:*:*:*:*:*:*:*"
        row={"schema":nvd.SCHEMA_VERSION,"kind":"query_complete","query":{"cpe_name":cpe},"cve_count":0}
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/"snapshot.jsonl"
            # Public read_jsonl contract: a BOM-prefixed UTF-8 snapshot is accepted.
            # parse_jsonl also strips a BOM deliberately, so this is end-to-end behavior,
            # not an assertion about which layer performs the stripping.
            path.write_bytes(b"\xef\xbb\xbf"+json.dumps(row).encode("utf-8"))
            self.assertEqual(nvd.read_jsonl(path),[row])
            path.write_text('{"schema":"wrong"}\n',encoding="utf-8")
            with self.assertRaises(ValueError):
                nvd.read_jsonl(path)

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
        record=summary("日本語")
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

    def test_cli_cpe_options(self):
        record=summary("test")
        with tempfile.TemporaryDirectory() as d:
            out=Path(d)/"out.jsonl"
            with mock.patch.object(nvd,"fetch_cves",return_value=[record]) as fetch:
                self.assertEqual(nvd.main(["--silent","--cpe","cpe:2.3:a:test:one:1:*:*:*:*:*:*:*","--output",str(out)]),0)
            self.assertEqual(fetch.call_args_list[0].args[0],"cpe:2.3:a:test:one:1:*:*:*:*:*:*:*")
            lines=[json.loads(line) for line in out.read_text(encoding="utf-8").split("\n") if line]
            self.assertEqual(lines[0]["query"]["cpe_name"],"cpe:2.3:a:test:one:1:*:*:*:*:*:*:*")

    def test_cli_cpe_multiple_and_deduplication(self):
        with mock.patch.object(nvd,"fetch_cves",return_value=[]) as fetch, mock.patch("sys.stdout", io.StringIO()):
            self.assertEqual(nvd.main(["--silent","--cpe","cpe:1","--cpe","cpe:2","--cpe","cpe:3","--cpe","cpe:1"]),0)
        self.assertEqual([call.args[0] for call in fetch.call_args_list],["cpe:1","cpe:2","cpe:3"])

    def test_cli_cpe_preserves_escaped_comma(self):
        cpe = r"cpe:2.3:a:example:product\,edition:1:*:*:*:*:*:*:*"
        with mock.patch.object(nvd,"fetch_cves",return_value=[]) as fetch, mock.patch("sys.stdout", io.StringIO()):
            self.assertEqual(nvd.main(["--silent","--cpe",cpe]),0)
        self.assertEqual([call.args[0] for call in fetch.call_args_list],[cpe])

    def test_cpe_name_alias_removed(self):
        stderr=io.StringIO()
        with mock.patch("sys.stderr",stderr):
            self.assertEqual(nvd.main(["--silent","--cpe-name","cpe:1"]),2)
        self.assertIn("unrecognized arguments", stderr.getvalue())

    def test_cli_no_cpe_or_config_error(self):
        stderr=io.StringIO()
        with mock.patch("sys.stderr",stderr):
            self.assertEqual(nvd.main(["--silent","--config","nonexistent.ini"]),2)
        self.assertIn("error:", stderr.getvalue())



def _run_cli(args, cwd):
    """Execute the CLI as a process. Callers must not pass arguments that query NVD."""
    return run_cli(
        ROOT / "nvd_nist_known_vulns.py",
        *args,
        python_options=("-S",),
        cwd=cwd,
        timeout=20,
    )


class CliProcessTests(unittest.TestCase):
    """Process-level help, exit codes, and JSON errors. These tests do not contact NVD."""

    def test_help_documents_every_flag_and_exit_status(self):
        with tempfile.TemporaryDirectory() as directory:
            completed = _run_cli(["--help"], directory)
        self.assertEqual(completed.returncode, nvd.EXIT_OK)
        self.assertEqual(completed.stderr, "")
        help_text = completed.stdout
        flat = " ".join(help_text.split())
        for flag in (
            "--silent",
            "--config",
            "--cpe",
            "--output",
            "--timeout",
            "--format",
            "--cvss-v3-severity",
            "--cvss-v3-metrics",
        ):
            self.assertIn(flag, flat)
        self.assertIn("progress", flat)
        self.assertIn("[cpeName]", flat)
        self.assertIn("not split on commas", flat)
        self.assertIn("Positive finite", flat)
        self.assertIn("nvd-cli-error/1", flat)
        self.assertIn("exit status:", help_text)
        self.assertIn("\n  0  success", help_text)
        self.assertIn("\n  1  the NVD request failed", help_text)
        self.assertIn("\n  2  usage or local input error", help_text)
        self.assertIn("LOW, MEDIUM, HIGH, or CRITICAL", flat)

    def test_usage_errors_exit_2_in_text_and_json(self):
        with tempfile.TemporaryDirectory() as directory:
            missing = str(Path(directory) / "missing.ini")
            cases = [
                (["--silent", "--config", missing], "text"),
                (["--silent", "--format", "text", "--config", missing], "text"),
                (["--silent", "--format", "json", "--format", "text", "--config", missing], "text"),
                (["--bogus"], "text"),
                (["--timeout", "0", "--config", missing], "text"),
                (["--timeout", "-1"], "text"),
                (["--timeout", "nan"], "text"),
                (["--cvss-v3-severity", "NOPE"], "text"),
                (["--format", "yaml"], "text"),
                (["--silent", "--format", "json", "--config", missing], "json"),
                (["--silent", "--format=json", "--config", missing], "json"),
                (["--format", "text", "--format", "json", "--config", missing], "json"),
                (["--bogus", "--format", "json"], "json"),
                (["--format", "json", "--timeout", "inf"], "json"),
            ]
            for args, kind in cases:
                with self.subTest(args=args, kind=kind):
                    completed = _run_cli(args, directory)
                    self.assertEqual(completed.returncode, nvd.EXIT_USAGE)
                    self.assertNotIn("Traceback", completed.stderr)
                    self.assertEqual(completed.stdout, "")
                    if kind == "json":
                        record = json.loads(completed.stderr)
                        self.assertEqual(record["schema"], nvd.ERROR_SCHEMA)
                        self.assertEqual(record["status"], "error")
                        self.assertEqual(record["category"], "usage")
                        self.assertEqual(record["exit_code"], nvd.EXIT_USAGE)
                        self.assertTrue(record["message"])
                        self.assertTrue(record["error"])
                    else:
                        self.assertIn("error:", completed.stderr)
                        self.assertNotIn(nvd.ERROR_SCHEMA, completed.stderr)

    def test_invalid_config_and_empty_cpe_list_exit_2(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            malformed = root / "bad.ini"
            malformed.write_text("[cpeName\n", encoding="utf-8")
            empty = root / "empty.ini"
            empty.write_text("[cpeName]\n", encoding="utf-8")
            for path in (malformed, empty):
                with self.subTest(path=path.name, fmt="text"):
                    completed = _run_cli(["--silent", "--config", str(path)], directory)
                    self.assertEqual(completed.returncode, nvd.EXIT_USAGE)
                    self.assertIn("error:", completed.stderr)
                    self.assertNotIn("Traceback", completed.stderr)
                with self.subTest(path=path.name, fmt="json"):
                    completed = _run_cli(
                        ["--format", "json", "--config", str(path)], directory
                    )
                    self.assertEqual(completed.returncode, nvd.EXIT_USAGE)
                    record = json.loads(completed.stderr)
                    self.assertEqual(record["category"], "usage")
                    self.assertEqual(record["exit_code"], 2)
                    self.assertEqual(record["schema"], "nvd-cli-error/1")
                    self.assertNotIn("Fetching", completed.stderr)

    def test_unpublished_output_exits_1_without_network(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory) / "not-a-directory"
            parent.write_text("occupied", encoding="utf-8")
            output = parent / "result.jsonl"
            cpe = "cpe:2.3:a:example:app:1:*:*:*:*:*:*:*"
            text = _run_cli(
                ["--silent", "--cpe", cpe, "--output", str(output), "--timeout", "1"],
                directory,
            )
            self.assertEqual(text.returncode, nvd.EXIT_RUNTIME)
            self.assertIn("error:", text.stderr)
            self.assertIn("directory", text.stderr.lower())
            self.assertNotIn("NVD HTTP", text.stderr)
            self.assertNotIn("Traceback", text.stderr)
            self.assertEqual(text.stdout, "")
            self.assertFalse(output.exists())
            json_run = _run_cli(
                ["--format", "json", "--cpe", cpe, "--output", str(output), "--timeout", "1"],
                directory,
            )
            self.assertEqual(json_run.returncode, nvd.EXIT_RUNTIME)
            record = json.loads(json_run.stderr)
            self.assertEqual(record["category"], "runtime")
            self.assertEqual(record["exit_code"], 1)
            self.assertEqual(record["status"], "error")
            self.assertEqual(record["schema"], nvd.ERROR_SCHEMA)
            self.assertNotEqual(record["error"], "usage")
            self.assertEqual(json_run.stdout, "")
            self.assertNotIn("Fetching", json_run.stderr)
            self.assertIn("directory", record["message"].lower())
            self.assertNotIn("NVD HTTP", record["message"])


class CliFormatTests(unittest.TestCase):
    def test_json_success_keeps_jsonl_and_skips_progress(self):
        record = summary("test")
        stderr = io.StringIO()
        stdout = io.StringIO()
        with mock.patch.object(nvd, "fetch_cves", return_value=[record]) as fetch, \
                mock.patch("sys.stderr", stderr), mock.patch("sys.stdout", stdout):
            code = nvd.main(["--format", "json", "--cpe", "cpe:1"])
        self.assertEqual(code, nvd.EXIT_OK)
        self.assertEqual(stderr.getvalue(), "")
        rows = [json.loads(line) for line in stdout.getvalue().split("\n") if line]
        self.assertEqual([row["kind"] for row in rows], ["cve", "query_complete"])
        self.assertEqual(fetch.call_args.kwargs["timeout"], 30.0)

    def test_text_progress_and_json_runtime_record(self):
        stderr = io.StringIO()
        with mock.patch.object(nvd, "fetch_cves", return_value=[]), \
                mock.patch("sys.stderr", stderr), mock.patch("sys.stdout", io.StringIO()):
            self.assertEqual(nvd.main(["--cpe", "cpe:1"]), 0)
        self.assertIn("Fetching NVD CVEs for cpe:1", stderr.getvalue())

        stderr = io.StringIO()
        stdout = io.StringIO()
        with mock.patch.object(nvd, "fetch_cves", side_effect=RuntimeError("boom")), \
                mock.patch("sys.stderr", stderr), mock.patch("sys.stdout", stdout):
            self.assertEqual(nvd.main(["--format", "json", "--cpe", "cpe:1"]), nvd.EXIT_RUNTIME)
        self.assertEqual(stdout.getvalue(), "")
        record = json.loads(stderr.getvalue())
        self.assertEqual(record, {
            "category": "runtime",
            "error": "RuntimeError",
            "exit_code": 1,
            "message": "boom",
            "schema": nvd.ERROR_SCHEMA,
            "status": "error",
        })

    def test_json_failure_after_partial_stdout_stays_on_stderr(self):
        ok = summary()
        stdout = io.StringIO()
        stderr = io.StringIO()
        with mock.patch.object(nvd, "fetch_cves", side_effect=[[ok], RuntimeError("boom")]), \
                mock.patch("sys.stdout", stdout), mock.patch("sys.stderr", stderr):
            code = nvd.main(["--format", "json", "--cpe", "cpe:ok", "--cpe", "cpe:failed"])
        self.assertEqual(code, 1)
        rows = [json.loads(line) for line in stdout.getvalue().split("\n") if line]
        self.assertEqual([row["kind"] for row in rows], ["cve", "query_complete"])
        self.assertEqual(json.loads(stderr.getvalue())["message"], "boom")
        self.assertNotIn("Fetching", stderr.getvalue())

    def test_output_path_failure_does_not_query_nvd(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory) / "not-a-directory"
            parent.write_text("occupied", encoding="utf-8")
            stderr = io.StringIO()
            with mock.patch.object(nvd, "fetch_cves") as fetch, mock.patch("sys.stderr", stderr):
                code = nvd.main([
                    "--silent", "--cpe", "cpe:2.3:a:example:app:1:*:*:*:*:*:*:*",
                    "--output", str(parent / "result.jsonl"),
                ])
        self.assertEqual(code, nvd.EXIT_RUNTIME)
        fetch.assert_not_called()
        self.assertIn("error:", stderr.getvalue())


# ── CPE helpers ───────────────────────────────────────────────────────────────────────────────────


def cpe(**fields):
    attrs = dict(part="a", vendor="vendoralpha", product="widget",
                 version="1.0", update="*", edition="*", language="*",
                 sw_edition="*", target_sw="*", target_hw="*", other="*")
    attrs.update(fields)
    return "cpe:2.3:" + ":".join(attrs.values())


class CpeHelperTests(unittest.TestCase):
    def test_all_attributes_and_logical_part_types(self):
        name = cpe(part="o", update="sp1", edition="enterprise", language="en-US",
                   sw_edition="desktop", target_sw="linux", target_hw="x64", other="extra")
        parsed = nvd.parse_cpe_name(name)
        self.assertEqual(parsed["part_type"], "operating_system")
        self.assertEqual(list(parsed["raw_attributes"].values()), name.split(":")[2:])
        for key, raw in parsed["raw_attributes"].items():
            self.assertEqual(parsed[key], raw)
        for part, kind in (("a", "application"), ("h", "hardware"),
                           ("A", "application"), ("*", "unknown"), ("-", "unknown")):
            with self.subTest(part=part):
                self.assertEqual(nvd.parse_cpe_name(cpe(part=part))["part_type"], kind)

    def test_escaped_delimiters_and_backslash_parity(self):
        for raw, display in ((r"one\:two", "one:two"), (r"one\,two", "one,two"),
                             (r"one\\", "one\\"), (r"one\\\:two", "one\\:two"),
                             (r"\*", "*"), (r"\?", "?")):
            with self.subTest(raw=raw):
                parsed = nvd.parse_cpe_name(cpe(product=raw))
                self.assertEqual(parsed["product"], display)
                self.assertEqual(parsed["raw_attributes"]["product"], raw)
                self.assertEqual(parsed["version"], "1.0")

    def test_every_permitted_quoted_punctuation(self):
        # NISTIR 7695 Figure 6-3, independent explicit alphabet.
        for char in '\\*?!"#$%&\'()+,/:;<=>@[]^`{|}~':
            with self.subTest(char=char):
                self.assertEqual(nvd.parse_cpe_name(cpe(product="\\" + char))["product"], char)

    def test_logical_and_literal_values_are_distinguishable(self):
        for key in ("vendor", "product", "version", "update", "edition", "other"):
            any_value = nvd.parse_cpe_name(cpe(**{key: "*"}))
            literal = nvd.parse_cpe_name(cpe(**{key: r"\*"}))
            na = nvd.parse_cpe_name(cpe(**{key: "-"}))
            with self.subTest(key=key):
                self.assertEqual(any_value[key], literal[key])  # display only
                self.assertNotEqual(any_value["raw_attributes"][key], literal["raw_attributes"][key])
                self.assertEqual(na["raw_attributes"][key], "-")

    def test_valid_wildcard_positions_and_language(self):
        for value in ("*", "-", "*foo", "foo*", "*foo*", "??foo?", "?foo??",
                      r"foo\*bar", r"foo\?bar", "1.*", "a-b_c.d"):
            with self.subTest(value=value):
                self.assertEqual(nvd.parse_cpe_name(cpe(version=value))["raw_attributes"]["version"], value)
        for language in ("en", "eng", "ja-JP", "es-419", "*", "-"):
            with self.subTest(language=language):
                self.assertEqual(nvd.parse_cpe_name(cpe(language=language))["language"], language)

    def test_invalid_structure_and_types(self):
        for value in (None, 123, [], {}, b"cpe:2.3:", "", "not_a_cpe",
                      cpe().replace("2.3", "2.2"), cpe().replace("cpe:2.3:", "cpe:/"),
                      cpe() + ":*", cpe().rsplit(":", 1)[0], cpe(other="abc\\")):
            with self.subTest(value=value), self.assertRaises(ValueError):
                nvd.parse_cpe_name(value)

    def test_invalid_attributes_escapes_and_wildcards(self):
        for key in ("vendor", "product", "version", "update", "edition", "sw_edition",
                    "target_sw", "target_hw", "other"):
            for value in ("", "two words", "x\ny", "x\ty", "x\x00y", "製品",
                          r"foo\a", r"foo\.", r"foo\-", r"foo\_", "foo,bar",
                          "foo*bar", "foo?bar", "**foo", "foo?*", "*?foo", "??"):
                with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                    nvd.parse_cpe_name(cpe(**{key: value}))
        for key, values in (("part", ("", "x", "application", r"\a")),
                            ("language", ("", "english", "e", "en_US", "en-*", "en-US-extra"))):
            for value in values:
                with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                    nvd.parse_cpe_name(cpe(**{key: value}))

    def test_other_vendor_product_version_can_still_be_suggestions(self):
        target = cpe()
        for candidate in (cpe(vendor="vendoromega"), cpe(product="widgets"),
                          cpe(version="2.0"), cpe(part="o")):
            with self.subTest(candidate=candidate):
                self.assertGreater(difflib.SequenceMatcher(None, target, candidate).ratio(), .8)
                self.assertEqual(nvd.suggest_cpe_names(target, [candidate], cutoff=.8), [candidate])
        # Raising cutoff to 1 requires identical spelling; it proves no CVE applicability.
        self.assertEqual(nvd.suggest_cpe_names(target, [cpe(version="2.0"), target], cutoff=1), [target])

    def test_suggestions_keep_original_escaping_and_do_not_expand_wildcards(self):
        names = [cpe(product=r"foo\:bar", version=v) for v in ("*", "1.0", r"\*")]
        self.assertEqual(nvd.suggest_cpe_names(names[0], names, cutoff=1), [names[0]])
        self.assertEqual(set(nvd.suggest_cpe_names(names[0], names, cutoff=0)), set(names))

    def test_suggestions_deduplicate_validate_and_support_generators(self):
        target = cpe()
        candidates = [target, target, None, 17, {}, "invalid", cpe(product=""), cpe(version="2")]
        original = list(candidates)
        self.assertEqual(nvd.suggest_cpe_names(target, iter(candidates), n=1), [target])
        matches = nvd.suggest_cpe_names(target, candidates, n=8, cutoff=0)
        self.assertEqual(matches, [target, cpe(version="2")])
        self.assertEqual(candidates, original)
        self.assertEqual(nvd.suggest_cpe_names(target, []), [])

    def test_invalid_suggestion_arguments_even_with_empty_candidates(self):
        for target in (None, "typo", cpe(product=""), cpe(other="bad\\")):
            with self.subTest(target=target), self.assertRaises(ValueError):
                nvd.suggest_cpe_names(target, [])
        for n in (0, -1, 1.5, True, "3", None):
            with self.subTest(n=n), self.assertRaises(ValueError):
                nvd.suggest_cpe_names(cpe(), [], n=n)
        for cutoff in (-.1, 1.1, float("nan"), float("inf"), True, ".8", None):
            with self.subTest(cutoff=cutoff), self.assertRaises(ValueError):
                nvd.suggest_cpe_names(cpe(), [], cutoff=cutoff)

    def test_helpers_are_offline(self):
        with mock.patch.object(nvd, "urlopen", side_effect=AssertionError("network")):
            self.assertEqual(nvd.suggest_cpe_names(cpe(), [cpe()]), [cpe()])

    def test_similar_cpe_does_not_supply_completion_or_cves(self):
        target, other = cpe(), cpe(vendor="vendoromega")
        records = nvd.parse_jsonl(nvd._record(other, {"id": "CVE-2026-0001"}) + "\n" +
                                  nvd._completion_record(other, 1))
        before = json.dumps(records, sort_keys=True)
        self.assertEqual(nvd.suggest_cpe_names(target, [other], cutoff=.8), [other])
        self.assertEqual(nvd.select_cpe_records(records, [target]), {
            "status": "not_measured", "reason": "missing_query_completion",
            "cpe_names": [target], "missing_cpe_names": [target]})
        records.append(json.loads(nvd._completion_record(target, 0)))
        self.assertEqual(nvd.select_cpe_records(records, [target]), {
            "status": "measured", "cpe_names": [target], "cve_count": 0, "cve_ids": []})
        self.assertEqual(json.dumps(records[:-1], sort_keys=True), before)

    def test_cli_fetch_and_jsonl_use_only_explicit_cpe(self):
        target = cpe(product=r"widget\,lib")
        fixture = {"vulnerabilities": [{"cve": {"id": "CVE-2026-0001",
                    "descriptions": [{"lang": "en", "value": "description 日本語"}]}}]}
        page = dict(fixture, startIndex=0, resultsPerPage=2000, totalResults=1)
        output = io.StringIO()
        with mock.patch.object(nvd, "parse_cpe_name", side_effect=AssertionError("parser used in query")), \
             mock.patch.object(nvd, "suggest_cpe_names", side_effect=AssertionError("fuzzy query")), \
             mock.patch.object(nvd, "_request_json", return_value=page) as request, \
             contextlib.redirect_stdout(output):
            self.assertEqual(nvd.main(["--silent", "--cpe", target]), 0)
        self.assertEqual(request.call_count, 1)
        self.assertEqual(parse_qs(urlsplit(request.call_args.args[0]).query)["cpeName"], [target])
        expected_record = {"id": "CVE-2026-0001", "description": "description 日本語",
                           "cwe": [], "cvss_v4": None, "cvss_v3": None, "cvss_v2": None,
                           "published": None, "last_modified": None, "source_identifier": None,
                           "schema": "nvd-cve-summary/1", "kind": "cve", "query": {"cpe_name": target}}
        expected_complete = {"schema": "nvd-cve-summary/1", "kind": "query_complete",
                             "query": {"cpe_name": target}, "cve_count": 1}
        expected = "".join(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n"
                           for row in (expected_record, expected_complete))
        self.assertEqual(output.getvalue(), expected)
        self.assertEqual(nvd.select_cpe_records(nvd.parse_jsonl(output.getvalue()), [target])["cve_ids"],
                         ["CVE-2026-0001"])

    def test_parse_cpe_name_valid(self):
        cpe = r"cpe:2.3:a:openssl:openssl\,lib:1.1.1c:*:*:*:*:*:*:*"
        parsed = nvd.parse_cpe_name(cpe)
        self.assertEqual(parsed["part"], "a")
        self.assertEqual(parsed["part_type"], "application")
        self.assertEqual(parsed["vendor"], "openssl")
        self.assertEqual(parsed["product"], "openssl,lib")
        self.assertEqual(parsed["version"], "1.1.1c")
        self.assertEqual(parsed["update"], "*")

    def test_parse_cpe_name_invalid(self):
        invalid_cpes = [
            "cpe:2.2:a:openssl:openssl:1.1.1c",
            "not_a_cpe",
            "cpe:2.3:a:openssl",
            123,
        ]
        for invalid in invalid_cpes:
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                nvd.parse_cpe_name(invalid)

    def test_suggest_cpe_names(self):
        candidates = [
            "cpe:2.3:a:openssl:openssl:1.1.1c:*:*:*:*:*:*:*",
            "cpe:2.3:a:openssl:openssl:1.1.1d:*:*:*:*:*:*:*",
            "cpe:2.3:a:apache:log4j:1.2:-:*:*:*:*:*:*",
        ]
        matches = nvd.suggest_cpe_names(
            "cpe:2.3:a:openssl:openssl:1.1.1a:*:*:*:*:*:*:*",
            candidates,
            cutoff=0.8,
        )
        self.assertIn("cpe:2.3:a:openssl:openssl:1.1.1c:*:*:*:*:*:*:*", matches)
        self.assertNotIn("cpe:2.3:a:apache:log4j:1.2:-:*:*:*:*:*:*", matches)

        with self.assertRaises(ValueError):
            nvd.suggest_cpe_names(None, candidates)


# ── query scope ───────────────────────────────────────────────────────────────────────────────────


CPE = 'cpe:2.3:a:example:app:1:*:*:*:*:*:*:*'


class QueryScopeTests(unittest.TestCase):
    def emit(self, flags, records):
        output = io.StringIO()
        with mock.patch.object(nvd, 'read_ini', return_value=[CPE]), mock.patch.object(nvd, 'fetch_cves', return_value=records) as fetch, contextlib.redirect_stdout(output):
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
        with mock.patch.object(nvd, 'fetch_cves') as fetch, contextlib.redirect_stdout(output), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(nvd.main(['--cvss-v3-metrics', '  ']), nvd.EXIT_USAGE)
        fetch.assert_not_called()
        self.assertEqual(output.getvalue(), '')


# ── CPE count index (pytest only) ─────────────────────────────────────────────────────────────────


def test_multiple_cpes_deduplicate_shared_ids_and_check_each_count():
    names=['cpe:2.3:a:example:a:1:*:*:*:*:*:*:*','cpe:2.3:a:example:b:1:*:*:*:*:*:*:*']
    rows=[]
    for name in names:
        rows += [{'kind':'cve','query':{'cpe_name':name},'id':ident} for ident in ('CVE-1','CVE-1','CVE-2')]
        rows.append({'kind':'query_complete','query':{'cpe_name':name},'cve_count':2})
    assert nvd.select_cpe_records(iter(rows),names)['cve_ids']==['CVE-1','CVE-2']
    rows[-1]['cve_count']=3
    assert nvd.select_cpe_records(rows,names)['mismatched_cpe_names']==[names[-1]]


if __name__ == "__main__":
    unittest.main()
