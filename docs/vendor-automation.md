# Public vendor placement and CI updates

The checked-in `vendor.lock.json` records each allowlisted source and LICENSE
file with its upstream commit, Git blob and SHA-256. Checked-in copies support
offline local tests; application runtime dependencies are unchanged. Git
attributes retain upstream bytes on Windows and Unix.

CI resolves and updates the allowlist once in a `resolve-vendor` job. That job
uploads the lock plus exact vendor bytes as `vendor-snapshot`; every OS/Python
job downloads that same snapshot, verifies it offline, then tests it. Upstream
changes during the matrix cannot select different source commits.

CI uses the shared stdlib tool at
`380d877cd85837f36cf6030d626ee8bb7dfa28cb`. It checks the baseline copies,
restores them from locked commits, then **automatically promotes** the allowlisted
files from their public upstream refs and runs the existing tests. Each upstream
ref resolves once per workflow run; the resulting full SHA and hashes are
recorded in the CI checkout before tests run. A separate Actions artifact
preserves the lock, optional `vendor-promotion.json` receipt, and vendor bytes
used by that run, including when tests fail. Unchanged selected bytes do not
churn the baseline pins. The updater itself stays at its reviewed full SHA.

There is no manual step required for normal push/PR CI. An ALM agent can use the
same commands after checking out the pinned shared tool in `.vendor-sync-tools`:

```sh
git clone https://github.com/myon-bioinformatics/myon-bioinformatics.git .vendor-sync-tools
git -C .vendor-sync-tools checkout 380d877cd85837f36cf6030d626ee8bb7dfa28cb
python -S .vendor-sync-tools/vendor_sync.py check
python -S .vendor-sync-tools/vendor_sync.py materialize
python -S .vendor-sync-tools/vendor_sync.py promote
python -S .vendor-sync-tools/vendor_sync.py check
python -S -m unittest discover -s tests -v
python -m pytest tests
```

A dispatch caller may select `vendor-mode=locked` to test only the recorded
baseline; default dispatch and ordinary push/PR CI use `update` mode, which runs
`promote` and keeps a `vendor-promotion.json` receipt. Offline local
pytest continues to use checked-in copies and does not initiate downloads.

Public source and metadata downloads are anonymous. API 403/429 uses a
temporary public Git snapshot with credential helpers disabled; it retains the
resolved SHA when available. Failure of both paths stays nonzero. No dedicated token, secret,
enable variable, scheduled PR creator, commit, push or automatic merge remains
in this vendor path. Both CI checkouts disable persisted Git credentials.
Changes exist only in the disposable run checkout and are not written back to
main. Existing test failures retain their exit status and evidence. Download,
hash-verification or unrecoverable fetch failures fail the update and CI; they never
silently fall back to old files. Existing JUnit/native artifact handling and
runtime policies are unchanged.


## Lock-derived evidence staging

Vendor artifact membership is now derived exclusively by the parent
`vendor_stage.py`, checked out with `vendor_sync.py` at full commit
`380d877cd85837f36cf6030d626ee8bb7dfa28cb`. Workflow uploads point to its generated
directory; adding a locked source or LICENSE needs no upload path-list edit.
Artifact names and repository-relative paths inside each artifact are preserved.
`vendor-evidence.json` is additional metadata with byte hashes and separate
locked/candidate, runtime receipt, and legacy projection classifications.
Earlier file counts in this document describe the pre-staging payload.

Staging runs even after a failed test, verifies every locked byte, and fails
nonzero on missing or modified members. It does not certify tests or promotion.
Locked runs exclude promotion receipts; candidate runs include one when present.
Legacy projection formats, when present, remain consumer-owned outputs of the
lock. Exact source pins, LICENSEs, test-only dependencies and Pages/MCP/runtime
behavior are unchanged. Central topology intent is owned by the parent's
`vendor-consumers.json`; recommended baselines belong to `vendor-catalog.json`;
this consumer's lock remains the authority for adopted bytes.
