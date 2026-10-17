# Public vendor placement and CI verification

The checked-in `vendor.lock.json` records each allowlisted source and LICENSE
file with its upstream commit, Git blob and SHA-256. Checked-in copies support
offline local tests; application runtime dependencies are unchanged. Git
attributes retain upstream bytes on Windows and Unix.

CI resolves the allowlist once in a `resolve-vendor` job. That job uploads the
lock plus exact vendor bytes as `vendor-snapshot`; every OS/Python job downloads
that same snapshot, verifies it offline, then tests it. Upstream changes during
the matrix cannot select different source commits.

CI uses the shared stdlib tool at
`1eda992aa6fa31a902e2c06428e53ab17e8fe3c1`. It checks the baseline copies,
restores them from locked commits, and records the resulting snapshot in a
separate Actions artifact used by that run, including when tests fail. The
placement tool itself stays at its reviewed full SHA. Automatic upstream
`promote` / `update` jobs are not part of this repository's CI.

There is no manual step required for normal push/PR CI. An ALM agent can use the
same commands after checking out the pinned shared tool in `.vendor-sync-tools`:

```sh
git clone https://github.com/myon-bioinformatics/myon-bioinformatics.git .vendor-sync-tools
git -C .vendor-sync-tools checkout 1eda992aa6fa31a902e2c06428e53ab17e8fe3c1
python -S .vendor-sync-tools/vendor_sync.py check --manifest vendor.lock.json
python -S .vendor-sync-tools/vendor_sync.py materialize --manifest vendor.lock.json
python -S .vendor-sync-tools/vendor_sync.py check --manifest vendor.lock.json
python -S -m unittest discover -s tests -v
python -m pytest tests
```

Offline local pytest continues to use checked-in copies and does not initiate
downloads.

Public source and metadata downloads are anonymous. API 403/429 uses a
temporary public Git snapshot with credential helpers disabled; it retains the
resolved SHA when available. Failure of both paths stays nonzero. No dedicated token, secret,
enable variable, scheduled PR creator, commit, push or automatic merge remains
in this vendor path. Both CI checkouts disable persisted Git credentials.
Changes exist only in the disposable run checkout and are not written back to
main. Existing test failures retain their exit status and evidence. Download,
hash-verification or unrecoverable fetch failures fail CI; they never silently
fall back to old files. Existing JUnit/native artifact handling and runtime
policies are unchanged.


## Lock-derived evidence staging

Vendor artifact membership is derived exclusively by the parent
`vendor_stage.py`, checked out with `vendor_sync.py` at full commit
`1eda992aa6fa31a902e2c06428e53ab17e8fe3c1`. Workflow uploads point to its
generated directory; adding a locked source or LICENSE needs no upload path-list
edit. Artifact names and repository-relative paths inside each artifact are
preserved. `vendor-evidence.json` is additional metadata with byte hashes and
separate locked/candidate, runtime receipt, and legacy projection
classifications.

Staging runs even after a failed test, verifies every locked byte, and fails
nonzero on missing or modified members. It does not certify tests or promotion.
Locked runs exclude promotion receipts. Legacy projection formats, when
present, remain consumer-owned outputs of the lock. Exact source pins,
LICENSEs, test-only dependencies and Pages/MCP/runtime behavior are unchanged.
Central topology intent is owned by the parent's `vendor-consumers.json`;
recommended baselines belong to `vendor-catalog.json`; this consumer's lock
remains the authority for adopted bytes.
