# Rust in `zcashd`

`zcashd` is primarily a C++ codebase, but most new code is being written in Rust
where possible.

## Auditing Rust dependencies

We use [`cargo-vet`] to audit our Rust dependencies. This means that after
adding a new dependency, or updating existing dependencies with `cargo update`,
CI will fail until corresponding audits have been added.

We also have a significant number of pre-existing unaudited dependency versions
that are excluded from auditing checks. We aim to reduce this list over time.
New entries should not be added to the exclusion list without justification.

To audit a dependency, first [install `cargo-vet`] and then follow the
["Performing Audits" guide]. If you are updating a dependency then instead of
auditing the new version in its entirety, you can optionally just audit the
delta between the old and new versions - even if the old version is in the
"unaudited" exclusion list.

[`cargo-vet`]: https://github.com/mozilla/cargo-vet
[install `cargo-vet`]: https://mozilla.github.io/cargo-vet/install.html
["Performing Audits" guide]: https://mozilla.github.io/cargo-vet/performing-audits.html

## Adding new dependencies in online-Rust mode

The `zcashd` build system pins all dependencies, and in order to facilitate
reproducible builds, `cargo` is configured to run in offline mode with vendored
crates. This means that if, for example, you add the `foobar` crate to
`Cargo.toml`, you will likely see an error similar to this:

```
$ cargo check
error: no matching package named `foobar` found
location searched: registry `https://github.com/rust-lang/crates.io-index`
required by package `librustzcash v0.2.0 (/path/to/zcash)`
```

To add dependencies that are compatible with the reproducible build system, you need to follow these steps:

1. First, if you've made changes to dependencies in `Cargo.toml`, these must be reverted before the next step:
    ```
    git stash
    ```
2. Next, reconfigure the build system for "online" mode:
    ```
    CONFIGURE_FLAGS=--enable-online-rust ./zcutil/build.sh
    ```
3. Now, introduce the dependency changes into `Cargo.toml`. If you saved changes in Step 1 with `git stash`, you can reapply them:
    ```
    git stash pop
    ```
4. Update `Cargo.lock`:
    ```
    cargo check
    ```
5. Commit the changes to `Cargo.toml` and `Cargo.lock` together:
    ```
    git commit ./Cargo.{toml,lock}
    ```
6. Verify the reproducible build works in vendored/offline mode without the `--enable-online-rust` flag:
    ```
    ./zcutil/build.sh
    ```

## Using a local Rust dependency

During development, you can use a locally checked out version of a dependency
by applying a [`cargo` patch](https://doc.rust-lang.org/cargo/reference/overriding-dependencies.html#the-patch-section).

For example, to use a local version of the `orchard` crate that includes a new
API, add the following patch to `Cargo.toml`:

```
[dependencies]
# This dependency is listed with a version, meaning it comes from crates.io; the
# patch goes into a [patch.crates-io] section.
orchard = "0.0"
...

[patch.crates-io]
# Comment out any existing patch, if present.
# orchard = { git = "https://github.com/zcash/orchard.git", rev = "..." }

# Add this patch (both relative and absolute paths work):
orchard = { path = "../relative/path/to/orchard" }
```

Usually you can apply a patch to use a locally checked out dependency without
needing to build `zcashd` in online-Rust mode. However, if your local changes
include a new dependency, you will need to ensure you are in online-Rust mode.
