# Vendored test adapter placement and updates

The application remains stdlib-only. The pytest adapter is test tooling, checked
in with its upstream license for offline local tests. `vendor.lock.json` is the
source of truth for both files: repository, fully qualified upstream branch,
immutable commit, source/destination paths, Git blob SHA and SHA-256.

The initial lock preserves the existing adapter and license bytes from xprobe
`326acd667e13b21bf53ccc1590af960edf8cbf6c`; this change does not update their code.
The old adapter-only provenance JSON is replaced by the lock, which covers the
license too. `vendor/* -text` prevents Git from rewriting the locked bytes.

## Verify or restore fixed versions

The Python CI matrix checks checked-in hashes, removes the two locked files,
restores them from their fixed source commits, then checks them again before
running the existing tests and evidence collector. Placement uses the stdlib
`vendor_sync.py` from the shared repository at
`ec71deac0b4232132130021037482b3f97670805`.

With that tool checked out locally, run from this repository root:

```sh
python -S /path/to/shared/vendor_sync.py check --manifest vendor.lock.json
python -S /path/to/shared/vendor_sync.py materialize --manifest vendor.lock.json
```

`check` is offline. `materialize` fetches only missing or incorrect bytes and
checks both hashes before placing them. Normal local tests require no network.

## Propose updates

`vendor-update.yml` calls the same reviewed shared commit weekly or on manual
dispatch. It is disabled unless `VENDOR_UPDATES_ENABLED` is exactly `true`.
No variable or secret is configured by this change.

After the yourself pilot has demonstrated a real update PR, its CI and duplicate
PR prevention, configure `VENDOR_UPDATE_TOKEN` using the dedicated GitHub App or
fine-grained PAT with contents/pull-request write access to this repository.
Then set the variable to `true` and manually dispatch the workflow to verify
this consumer. Setting it back to `false` disables proposals.

The shared updater resolves the upstream branch once, verifies each fetched
file against GitHub's blob metadata, and proposes changed bytes and lock pins
together. It does not auto-merge or run candidate Python files itself. Review
the source/license changes and this repository's CI before merging a proposal.
If the bytes are unchanged, no update PR is created.

When updating the shared automation itself, change the Python workflow checkout
ref, reusable workflow ref and `tool-commit` together; a regression check guards
against mixed tool versions. Shared behavior and token setup are documented in
the [shared vendor automation guide](https://github.com/myon-bioinformatics/myon-bioinformatics/blob/ec71deac0b4232132130021037482b3f97670805/docs/vendor-automation.md).
