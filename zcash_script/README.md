## zcash_script

[![Latest Version][version-badge]][version-url]
[![Rust Documentation][docs-badge]][docs-url]

[version-badge]: https://img.shields.io/crates/v/zcash_script.svg
[version-url]: https://crates.io/crates/zcash_script
[docs-badge]: https://img.shields.io/badge/docs-latest-blue.svg
[docs-url]: https://docs.rs/zcash_script

Rust implementation of the Zcash Script language..

### Publishing New Releases

This crate maintains **two concurrent release lines**: a `main`-based release (`0.5.x`) and a
backport release on a separate branch (`0.4.x`). Both must be released together when
publishing fixes that apply to both lines.

#### Main-line release (`0.5.x`)

1. Decide the release level (`patch`, `minor`, or `major`).
2. Bump the version and apply changelog/doc replacements:
   ```bash
   cargo release version --verbose --execute --allow-branch '*' -p zcash_script patch # [ major | minor ]
   cargo release replace --verbose --execute --allow-branch '*' -p zcash_script
   ```
3. Update `CHANGELOG.md`.
4. Open a PR with the changes, get it reviewed, and wait for CI to pass.
5. Create a [new GitHub release](https://github.com/ZcashFoundation/zcash_script/releases/new) for the tag.
6. Publish the crate:
   ```bash
   cargo release publish --verbose --execute -p zcash_script
   ```

#### Backport release (`0.4.x`)

1. Create a new branch from the previous release tag (e.g. `zcash_script-v0.4.2`):
   ```bash
   git checkout -b backport/zcash_script-0.4.3 zcash_script-v0.4.2
   ```
2. Cherry-pick the relevant commits from `main` (excluding release/merge commits).
3. Bump the version and apply replacements on the backport branch:
   ```bash
   cargo release version --verbose --execute --allow-branch '*' -p zcash_script patch
   cargo release replace --verbose --execute --allow-branch '*' -p zcash_script
   ```
4. Update `CHANGELOG.md`.
5. Open a PR with the backport changes, get it reviewed, and wait for CI to pass.
6. Create a [new GitHub release](https://github.com/ZcashFoundation/zcash_script/releases/new) for the tag.
7. Publish the crate from the backport tag:
   ```bash
   cargo release publish --verbose --execute -p zcash_script
   ```
