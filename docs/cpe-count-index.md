# Group CVE IDs once for completion-count validation

`select_cpe_records` now groups distinct CVE IDs by requested CPE after completion
receipts have been validated. It avoids rescanning every row for each requested
CPE and reuses the grouped sets for the final ID union. Missing, conflicting and
count-mismatch evidence still prevents a measured result. Filtered query rows
remain excluded. No network, scoring, schema or dependency changes.

```sh
uv run pytest -q
python -S -m scripts.benchmark_cpe_count_index
```

Full local suite: 80 passed, 8 skipped, 374 subtests passed (CPython 3.14.9).
Added test covers multiple CPEs, duplicate/shared CVE IDs, iterator input and an
individual completion-count mismatch.

Synthetic 100 requested CPEs / 10100 rows, CPython 3.12.14/Linux, one warmup plus
three alternating samples: median 84.124 → 3.300 ms. Complete result equality is
checked against the pinned git baseline; raw samples in cpe-count-measurement.json.
This stresses batch selection, not fetching or normal single-CPE latency. Grouped
sets add memory (not measured); no build/CI/total-memory improvement is claimed.
