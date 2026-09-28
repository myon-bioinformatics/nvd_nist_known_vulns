# NVD NIST known vulnerabilities

Single-file, Python-standard-library client for the NVD CVE API 2.0. It fetches vulnerabilities for CPE 2.3 names and emits deterministic JSON Lines suitable for CLI use, CI, offline processing, and cross-repository adapters.

## Features

- NVD CVE API 2.0 with exact `cpeName` queries.
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
python nvd_nist_known_vulns.py --silent --output result.jsonl\npython nvd_nist_known_vulns.py --config other.ini --timeout 30
```

An NVD API key is optional. When supplied it is read from the environment and sent as an HTTP header, not placed in the URL:

```bash
NVD_API_KEY=... python nvd_nist_known_vulns.py
```

## Reuse contract

The module is intentionally kept as one stdlib-only file. Other repositories may import `api_call`, `iter_cve_pages`, `format_cve_data`, or `fetch_cves`. Network access is isolated from normalization so consumers can use captured NVD JSON fixtures in tests.

The emitted JSONL schema is versioned as `nvd-cve-summary/1`. Additive fields may be introduced within v1; incompatible shape changes require a new schema version. NVD `published` and `lastModified` timestamps are UTC values as supplied by NVD. CVSS selection prefers a `Primary` metric and records its `source` and `type`.\n\nNetwork calls are throttled conservatively (6 seconds without an API key; 0.6 seconds with one). Transient 429/5xx responses and unauthenticated 403 responses are retried with bounded backoff. `--output` is written atomically: a failed run leaves an existing output file unchanged.

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

## NVD notice\n\nThis product uses data from the NVD API but is not endorsed or certified by the NVD.\n\n## License

MIT
