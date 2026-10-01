# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

<!-- next-header -->

## [Unreleased] - ReleaseDate

## [0.2.0] - 2026-09-30

### Changed

- Migrated to `zcash_script 0.6`.
- MSRV is now 1.85.
- The bundled `secp256k1` library is now libsecp256k1 0.8.0 (previously 0.2.0),
  the release that `secp256k1-sys 0.14` vendors. It enables the same modules as
  `secp256k1-sys`, so building with `--cfg rust_secp_no_symbol_renaming` links
  the Rust `secp256k1` bindings against it, leaving a single copy of
  libsecp256k1 in the final artifact.

### Fixed

- The bundled `secp256k1` library is now linked after `libzcash_script`, under a
  name that does not collide with the library built by `secp256k1-sys`. This
  fixes a link failure when building against `secp256k1-sys 0.14`.

## [0.1.0] - 2025-09-25

This crate was extracted from `zcash_script 0.3.2` and then modified to align with
`zcash_script 0.4.0`.

<!-- next-url -->
[Unreleased]: https://github.com/ZcashFoundation/zcash_script/compare/libzcash_script-v0.2.0...HEAD
[0.2.0]: https://github.com/ZcashFoundation/zcash_script/compare/libzcash_script-v0.1.0...libzcash_script-v0.2.0
[0.1.0]: https://github.com/ZcashFoundation/zcash_script/releases/tag/libzcash_script-v0.1.0
