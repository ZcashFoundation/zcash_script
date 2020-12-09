# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

<!-- next-header -->

## [Unreleased] - ReleaseDate
### Changed
- Updated `depend/zcash` to new version including a precompute API

## [0.1.4] - 2020-11-17
### Changed
- switched from bindgen `0.55` to bindgen `0.54` to avoid a dependency
  conflict with `rocksdb`

## [0.1.3] - 2020-10-09
### Changed
- Enabled endomorphism optimization
- Changed zcash dependency from a submodule to a subtree

### Fixed
- Can now run `cargo publish` and `cargo release` without errors

## [0.1.2] - 2020-09-21
### Removed
- dependency on `color-eyre` in build.rs

## [0.1.1] - 2020-09-15
### Changed
- enabled the `parallel` feature of `cc` to enable parallel compilation

### Security
- Updated `bindgen` to a non yanked version

<!-- next-url -->
[Unreleased]: https://github.com/ZcashFoundation/zcash_script/compare/v0.1.4...HEAD
[0.1.4]: https://github.com/ZcashFoundation/zcash_script/compare/v0.1.3...v0.1.4
[0.1.3]: https://github.com/ZcashFoundation/zcash_script/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/ZcashFoundation/zcash_script/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/ZcashFoundation/zcash_script/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/ZcashFoundation/zcash_script/releases/tag/v0.1.0
