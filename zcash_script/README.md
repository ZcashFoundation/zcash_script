## zcash_script

[![Latest Version][version-badge]][version-url]
[![Rust Documentation][docs-badge]][docs-url]

[version-badge]: https://img.shields.io/crates/v/zcash_script.svg
[version-url]: https://crates.io/crates/zcash_script
[docs-badge]: https://img.shields.io/badge/docs-latest-blue.svg
[docs-url]: https://docs.rs/zcash_script

Rust implementation of the Zcash Script language..

### Publishing New Releases

Releases for `zcash-script` are made with the help of [cargo release](https://github.com/sunng87/cargo-release).

1. Update `CHANGELOG.md` to document any major changes since the last release
2. Run `cargo release <level>` to commit the release version bump (but not actually publish), `<level>` can be `patch`, `minor` or `major`
3. Open a `zcash_script` PR with the changes, get it reviewed, and wait for CI to pass
4. Publish a new release using `cargo release --execute <level>`

**NOTE**: It's important to specify the level when using cargo release because of the way it implements the substitutions. We specify a number of automatic substitutions in `Cargo.toml` but they will only be applied if `cargo release` also handles incrementing the version itself, **do not increment the version by hand and then run `cargo release` or `cargo release -- release`, or it will not correctly update all version references in the codebase.**
