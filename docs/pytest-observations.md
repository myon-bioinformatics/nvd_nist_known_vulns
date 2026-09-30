# Native pytest evidence

CI writes `reports/pytest-events.jsonl` through the shared xprobe pytest adapter
and preserves it with the JUnit report, including when tests fail. All Python matrix jobs use the adapter. The runtime the application remains stdlib-only.

For local runs, choose a fresh destination (existing evidence is never overwritten):

```sh
python -m pytest -p vendor.xprobe_pytest --xprobe-jsonl=reports/local-001.jsonl --xprobe-repository=myon-bioinformatics/nvd_nist_known_vulns
```

The vendored adapter is byte-for-byte from xprobe commit
`326acd667e13b21bf53ccc1590af960edf8cbf6c`, `scripts/xprobe_pytest.py`.
Its license and SHA-256/Git blob provenance live alongside it in `vendor/`.
Update from a reviewed upstream commit and refresh the provenance together.

Records distinguish setup/call/teardown and collection, with native failure,
error, skip, xfail, xpass and strict XPASS outcomes. Records describe phases,
not one final result per test. A finish record's `complete` means no observations
were dropped; it does not mean tests passed. Missing finish means partial evidence.
The pytest exit status is preserved. Serial pytest only; xdist is not supported.

Repository identity is explicit. Commit SHA stays null until supplied from the
canonical metadata producer; GitHub's environment SHA is not substituted.
Tracebacks, captured output, marker reasons and parameter labels are omitted.
Test names remain visible, and node hashes are not encryption. Reports are
14-day Actions artifacts, not published Pages content.

## Explore downloaded reports

Using an xprobe checkout at the same commit (replace paths with your locations):

```sh
python /path/to/xprobe/scripts/xprobe_cli.py '"outcome": "xfail"' /path/to/downloaded-reports --include '*.jsonl'
python /path/to/xprobe/scripts/xprobe_cli.py '"phase": "teardown"' /path/to/downloaded-reports --include '*.jsonl'
```

For structured use, load the JSONL with `xprobe.corpus_from_json(text, jsonl=True)`.
Keep downloaded artifacts in separate job directories so identical filenames
do not overwrite each other. Run IDs distinguish observations across jobs.

Reproduction inputs and chat-text references must be explicit, reviewed records
linked by `origin_id`; this adapter does not infer causes or ingest chat history.
