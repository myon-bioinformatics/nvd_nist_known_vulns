# NVD NIST known vulnerabilities

**Python compatibility:** CI-tested on Python 3.9–3.14.
Single-file, Python-standard-library client for the NVD CVE API 2.0. It fetches vulnerabilities for CPE 2.3 names and emits deterministic JSON Lines suitable for CLI use, CI, offline processing, and cross-repository adapters.

NVD’s public CVE REST stem remains `/rest/json/cves/2.0` (a `/cves/3.0` probe returns 404). This client stays on 2.0 and adds CVSS v3-series request filters plus local CVSS base-score calculation for v2 / v3.0 / v3.1 vectors.

## Features

- NVD CVE API 2.0 with exact `cpeName` queries.
- Optional CVSS v3-series filters: `--cvss-v3-severity` / `--cvss-v3-metrics` (NVD `cvssV3Severity` / `cvssV3Metrics`).
- Local CVSS base-score calculation for v2.0 / v3.0 / v3.1 vector strings (`calculate_cvss_base`); metric records also carry `calculated_base_score` when a vector is present.
- No third-party runtime dependencies.
- Pagination: results are not silently truncated to one page.
- Optional `NVD_API_KEY` header support.
- Rate-limit throttling, bounded retry/backoff for transient HTTP failures, and non-zero CLI failure status.
- Stable `nvd-cve-summary/1` JSONL records with CVSS v4/v3/v2, CWE, dates, and source identifier.
- Offline unit tests that run with `python -S`.

## Configure

`config.ini` keeps the existing CPE-list contract:

```ini
[cpeName]
cpe1 = cpe:2.3:a:openssl:openssl:1.1.1c:*:*:*:*:*:*:*
cpe2 = cpe:2.3:a:apache:log4j:1.2:-:*:*:*:*:*:*
```

## Run

```bash
python nvd_nist_known_vulns.py
python nvd_nist_known_vulns.py --silent --output result.jsonl
python nvd_nist_known_vulns.py --config other.ini --timeout 30
python nvd_nist_known_vulns.py --cvss-v3-severity CRITICAL
```

An NVD API key is optional. When supplied it is read from the environment and sent as an HTTP header, not placed in the URL:

```bash
NVD_API_KEY=... python nvd_nist_known_vulns.py
```

## Reuse contract

The module is intentionally kept as one stdlib-only file. Other repositories may import `api_call`, `iter_cve_pages`, `format_cve_data`, `fetch_cves`, `calculate_cvss_base`, `parse_jsonl`, `read_jsonl`, or `select_cpe_records`. The JSONL helpers validate completion evidence, distinguish an unmeasured/incomplete CPE from a measured zero-result CPE, and deduplicate a CVE that matches multiple selected CPEs. Network access is isolated from normalization so consumers can use captured NVD JSON fixtures in tests. `calculate_cvss_base` is pure and offline; it implements FIRST CVSS v2 / v3.0 / v3.1 base equations and rejects v4 MacroVector lookup vectors.

The emitted JSONL schema is versioned as `nvd-cve-summary/1`. Records use `kind: "cve"` or `kind: "query_complete"`. A successful CPE query emits its CVE records first and exactly one `query_complete` record afterward, including when the result count is zero. A completion record is emitted only after pagination has been validated as complete; if it is absent, consumers must treat that CPE as not measured or failed rather than as zero vulnerabilities. Early v1 CVE records without `kind` may be treated as `cve`. V1 consumers must dispatch on `kind` and ignore unknown kinds so future additive record kinds do not break them. Additive fields and record kinds following that rule may be introduced within v1; other incompatible shape changes require a new schema version. NVD `published` and `lastModified` timestamps are UTC values as supplied by NVD. CVSS selection prefers a `Primary` metric and records its `source` and `type`. When a metric includes a calculable vector, the record also adds `calculated_base_score` and `calculated_base_severity` beside the NVD-supplied score.

Network calls are throttled conservatively (6 seconds without an API key; 0.6 seconds with one). Transient 429/5xx responses and unauthenticated 403 responses are retried with bounded backoff. `--output` is written atomically: a failed run leaves an existing output file unchanged.

## Testing

```bash
python -S -m py_compile nvd_nist_known_vulns.py
python -S -m unittest discover -s tests -v
```

Tests are offline and do not consume NVD rate limits.

## Migration note

The original implementation used `requests` and printed Python `set` values. This revision removes that dependency and changes the machine-readable output to deterministic JSONL. The `config.ini` CPE input and `--silent` option remain supported.

## References

- NVD CVE API 2.0: https://nvd.nist.gov/developers/vulnerabilities
- NVD developer start: https://nvd.nist.gov/developers/start-here

## NVD notice

This product uses data from the NVD API but is not endorsed or certified by the NVD.

## License

MIT

## Test evidence

Install test-only tools with `python -m pip install -r tests/requirements.txt`.
CI preserves native pytest JSONL and JUnit while retaining the `python -S`
runtime isolation lane. See [recording and exploration](docs/pytest-observations.md).


### Filtered query completion

CVSS-filtered requests emit `filtered_cve` and `filtered_query_complete` kinds
within `nvd-cve-summary/1`. Both carry the same `query.filters`, using
`cvss_v3_severity` and/or `cvss_v3_metrics`; values are trimmed and uppercased
before both the request and JSONL output. The completion count belongs only to
that filtered request, including zero results. Unfiltered output keeps its
existing `cve` / `query_complete` kinds and CPE-only query unchanged.

This kind separation is required for older v1 readers, which ignore unknown
kinds: merely adding filter fields to `query_complete` would let them mistake
a filtered zero for a complete unfiltered measurement. `parse_jsonl` understands
the new kinds and rejects missing, invalid or ambiguous filter scopes.
`select_cpe_records` remains an **unfiltered** selector: filtered rows and query
restrictions do not supply completion, counts or CVE IDs. A snapshot with only
filtered evidence returns `not_measured`, and mixed snapshots use only the
unfiltered evidence. Consumers needing filtered results can inspect the explicit
filtered records returned by `parse_jsonl`.
