## zcash_script

[![Build Status][actions-badge]][actions-url]
[![Latest Version][version-badge]][version-url]
[![Rust Documentation][docs-badge]][docs-url]

[actions-badge]: https://github.com/ZcashFoundation/zcash_script/workflows/Continuous%20integration/badge.svg
[actions-url]: https://github.com/ZcashFoundation/zcash_script/actions?query=workflow%3A%22Continuous+integration%22
[version-badge]: https://img.shields.io/crates/v/zcash_script.svg
[version-url]: https://crates.io/crates/zcash_script
[docs-badge]: https://img.shields.io/badge/docs-latest-blue.svg
[docs-url]: https://docs.rs/zcash_script

Rust bindings to the ECC's `zcash_script` c++ library.

### Updating `depend/zcash`

To pull in recent changes from the upstream repo run the following:

```console
git subtree pull -P depend/zcash <repo> <branch> --squash
```

For example:

```console
git subtree pull -P depend/zcash https://github.com/str4d/zcash.git zcash-script-precompute --squash
```

### Publishing New Releases

Releases for `zcash-script` are made with the help of [cargo release](https://github.com/sunng87/cargo-release).

**Checklist:**

* create a new branch batch the release commits into a PR
* update `CHANGELOG.md` to document any major changes since the last release
* open a PR to merge your branch into `master`
* locally run `cargo release -- <level>` where `level` can be `patch`, `minor`, or `major` ([source](https://github.com/sunng87/cargo-release/blob/master/docs/reference.md#bump-level))

**NOTE**: It's important to specify the level when using cargo release because of the way it implements the substitutions. We specify a number of automatic substitutions in `Cargo.toml` but they will only be applied if `cargo release` also handles incrementing the version itself, **do not increment the version by hand and then run `cargo release` or `cargo release -- release`, or it will not correctly update all version references in the codebase.**
