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
into a single library. Due to the way the `zcash_script` is written we unfortunately need
to include a lot of other stuff e.g. the orchard library.

### Updating this crate

1. Create a new branch batch so all the release commits can be made into a PR
2. Update `depend/zcash` with the latest tagged version of `zcashd`, using the instructions below
3. Update `Cargo.toml` versions to match the versions used by the latest tagged version of `zcashd`, and its dependencies
4. For dependencies that are shared with Zebra (but not `zcashd`), match the latest version in Zebra's [Cargo.lock](https://github.com/ZcashFoundation/zebra/blob/main/Cargo.lock):
    - use `cargo tree --invert <crate>` to see if the crate is from `zcash_script` or another dependency
    - see the list in [Cargo.toml](https://github.com/ZcashFoundation/zcash_script/blob/master/Cargo.toml#L69)
5. For new dependencies with a leading zero in their version (`0.x.y`), use a `>=` dependency [to make them automatically upgrade to match Zebra's dependencies](https://doc.rust-lang.org/cargo/reference/resolver.html#semver-compatibility)
6. Test if everything works by running `cargo test`. If you get any compiling errors, see
   the troubleshooting section below.
7. Check all open PRs to see if they can be merged before the release
8. Do the release, following the instructions below
9. Check the release tag was pushed to https://github.com/ZcashFoundation/zcash_script/tags

### Updating `depend/zcash`

We keep a copy of the zcash source in `depend/zcash` with the help of `git subtree`.
It has one single difference that must be enforced every time it's updated: the root
`Cargo.toml` must be deleted, since otherwise cargo will ignore the entire folder
when publishing the crate (see https://github.com/rust-lang/cargo/issues/8597).

However, `git subtree` requires merge commits in order to make further updates
work correctly. Since we don't allow those in our repository, we start over
every time, basically using it as a glorified `git clone`. This issue is being
tracked in https://github.com/ZcashFoundation/zcash_script/issues/35.

We also need to patch the zcash source to enable Windows compatibility. This
is done by applying a patch file as described below. If the patch application
fails, check the patch file for reference on what needs to be changed (and
update the patch file).

If you need to update the zcash source, run:

```console
git rm -r depend/zcash
(commit changes)
git subtree add -P depend/zcash https://github.com/zcash/zcash.git <ref> --squash
git rm depend/zcash/Cargo.toml
git apply zcash.patch
(commit changes)
```

where `<ref>` is a reference to a branch, tag or commit (it should be a tag when preparing
a release, but it will be likely a branch or commit when testing).

### Updating `Cargo.toml`

Note that `zcash_script` (the C++ library/folder inside `zcash`) uses some Rust
FFI functions from `zcash`; and it also links to `librustzcash` which is written in Rust.
Therefore, when updating `zcash_script` (this crate), we need to make sure that shared dependencies
between all of those are the same versions (and are patched to the same revisions, if applicable).
To do that, check for versions in:

- `zcash/Cargo.toml` in the revision pointed to by this crate (also check for patches)
- `librustzcash/Cargo.toml` in the revision pointed to by `zcash` (also check for patches)
- `librustzcash/<crate>/Cargo.toml` in the revision pointed to by `zcash`
- `orchard/Cargo.toml` in the revision pointed to by `zcash` (also check for patches)

To double-check, you can use `cargo tree` or `cargo deny check bans` on Zebra,
once the `zcash_script`, `librustzcash`, and `orchard` versions have all been updated.

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