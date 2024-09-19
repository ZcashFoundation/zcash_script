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

Rust bindings to the ECC's `zcash_script` C++ library.

### Developing

This crate works by manually including the `zcash_script` .h and .cpp files,
using `bindgen` to generate Rust bindings, and compiling everything together
into a single library.

### Updating this crate

1. Create a new branch batch so all the release commits can be made into a PR
2. Update `depend/zcash` with the latest tagged version of `zcashd`, using the instructions below
6. Test if everything works by running `cargo test`. If you get any compiling errors, see
   the troubleshooting section below.
7. Check all open PRs to see if they can be merged before the release
8. Do the release, following the instructions below
9. Check the release tag was pushed to https://github.com/ZcashFoundation/zcash_script/tags

### Updating `depend/zcash`

We keep a copy of the zcash source in `depend/zcash`, but it has diverged
in 0.2.0 release (based on zcashd 5.9.0) with the following changes:

- The root `Cargo.toml` was be deleted, since otherwise cargo will ignore the
  entire folder when publishing the crate (see
  https://github.com/rust-lang/cargo/issues/8597).
- New classes were introduced in interpreter.h/.cpp to support the callback API.
- Some #if guards were added to remove code that is not needed for script
  verification.

The simplified API now mostly require files that are truly required for script
verification. These are unlikely to change so this crate no longers need to keep
the zcashd source in sync, unless there was some bug fix in script verification.

If updating zcashd source is required, you will need to manually update the
`depend/zcash` source tree and reapply changes that have been made to it. If
you do that, please document the process in detail in this file.

### Publishing New Releases

Releases for `zcash-script` are made with the help of [cargo release](https://github.com/sunng87/cargo-release).

1. Update `CHANGELOG.md` to document any major changes since the last release
2. Run `cargo release <level>` to commit the release version bump (but not actually publish), `<level>` can be `patch`, `minor` or `major`
3. Open a `zcash_script` PR with the changes, get it reviewed, and wait for CI to pass
4. Publish a new release using `cargo release --execute <level>`

**NOTE**: It's important to specify the level when using cargo release because of the way it implements the substitutions. We specify a number of automatic substitutions in `Cargo.toml` but they will only be applied if `cargo release` also handles incrementing the version itself, **do not increment the version by hand and then run `cargo release` or `cargo release -- release`, or it will not correctly update all version references in the codebase.**


### Troubleshooting

#### "undefined reference to `name`"

This likely means that a `.c` file is not being included in `build.rs`.
Search for `name` in the zcashd source tree to find which file contains it,
and add it to a  `file()` call inside `build.rs`.

#### "fatal error: `file`: No such file or directory"

This likely means that a `.h` file is not being found.
Seach for a file with the given name and add its folder to a `.include()`
call in `build.rs`. If the file does not exist there it's likely from
a 3rd-party dependency that is downloaded at build time. Search for
the file name on some search engine to attempt to find what project
it belongs to, cross-referencing the `depends/packages` folder
in `zcashd`. Then you may need to copy those files to a folder
inside `zcash_script` like we did in `depend/expected`.