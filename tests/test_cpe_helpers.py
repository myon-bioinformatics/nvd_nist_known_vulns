"""CPE suggestions are spelling aids, never product applicability evidence."""
import contextlib
import difflib
import io
import json
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

import nvd_nist_known_vulns as nvd


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
        with patch.object(nvd, "urlopen", side_effect=AssertionError("network")):
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
        with patch.object(nvd, "parse_cpe_name", side_effect=AssertionError("parser used in query")), \
             patch.object(nvd, "suggest_cpe_names", side_effect=AssertionError("fuzzy query")), \
             patch.object(nvd, "_request_json", return_value=page) as request, \
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
