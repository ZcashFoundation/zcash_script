## zcash_script

[![Latest Version][version-badge]][version-url]
[![Rust Documentation][docs-badge]][docs-url]

[version-badge]: https://img.shields.io/crates/v/zcash_script.svg
[version-url]: https://crates.io/crates/zcash_script
[docs-badge]: https://img.shields.io/badge/docs-latest-blue.svg
[docs-url]: https://docs.rs/zcash_script

Rust implementation of the Zcash Script language..

### Publishing New Releases

- Decide level of the release.
- Bump the crate versions:
```bash
cargo release version --verbose --execute --allow-branch '*' -p zcash_script patch # [ major | minor ]
cargo release replace --verbose --execute --allow-branch '*' -p zcash_script
```
- Update the crate CHANGELOG.md
- Open a `zcash_script` PR with the changes, get it reviewed, and wait for CI to pass
- Create a [new github release](https://github.com/ZcashFoundation/zcash_script/releases/new)
- Publish the crate:
```bash
cargo release publish --verbose --execute -p zcash_script
```
