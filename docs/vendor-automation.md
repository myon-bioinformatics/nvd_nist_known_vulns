# Public vendor placement and CI updates

The checked-in `vendor.lock.json` records each allowlisted source and LICENSE
file with its upstream commit, Git blob and SHA-256. Checked-in copies support
offline local tests; application runtime dependencies are unchanged. Git
attributes retain upstream bytes on Windows and Unix.

CI uses the shared stdlib tool at
`621ff651a25e583e62d7d562a01b0340674366f8`. It checks the baseline copies,
restores them from locked commits, then **automatically updates** the allowlisted
files from their public upstream refs and runs the existing tests. Each upstream
ref resolves once per update command; the resulting full SHA and hashes are
recorded in the CI checkout before tests run. A separate Actions artifact
preserves the lock used by that run, including when tests fail. Unchanged selected bytes do not
churn the baseline pins. The updater itself stays at its reviewed full SHA.

There is no manual step required for normal push/PR CI. An ALM agent can use the
same commands after checking out the pinned shared tool in `.vendor-sync-tools`:

```sh
python -S .vendor-sync-tools/vendor_sync.py check
python -S .vendor-sync-tools/vendor_sync.py materialize
python -S .vendor-sync-tools/vendor_sync.py update
python -S .vendor-sync-tools/vendor_sync.py check
python -m pytest
```

A dispatch caller may select `vendor-mode=locked` to test only the recorded
baseline; default dispatch and ordinary push/PR CI use `update`. Offline local
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
Pages/runtime policies are unchanged.
