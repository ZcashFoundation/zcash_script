# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

<!-- next-header -->

## [Unreleased] - ReleaseDate

### Changed

- MSRV is now 1.85.

### Fixed

- The bundled `secp256k1` library is now linked after `libzcash_script`, under a
  name that does not collide with the library built by `secp256k1-sys`. This
  fixes a link failure when building against `secp256k1-sys 0.14`.

## [0.1.0] - 2025-09-25

This crate was extracted from `zcash_script 0.3.2` and then modified to align with
`zcash_script 0.4.0`.

<!-- next-url -->
[Unreleased]: https://github.com/ZcashFoundation/zcash_script/compare/libzcash_script-v0.1.0...HEAD
[0.1.0]: https://github.com/ZcashFoundation/zcash_script/releases/tag/libzcash_script-v0.1.0
