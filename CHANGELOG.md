# Changelog

All notable changes to this project will be documented in this file.

## [0.2.0] - 2026-06-30

### Added

- Detection and verification of existing integrity artifacts:
  - Checksum files (`SHA256SUMS`, `MD5SUMS`, `SHA1SUMS`, `SHA512SUMS` and `.md5`/`.sha1`/`.sha256`/`.sha512`).
  - Detached signatures (`.asc`, `.sig`, `.sign`) verified with GPG.
  - Results are printed to the console and recorded in the report under **EXISTING INTEGRITY ARTIFACTS**.
- Default report footer with tool version and repository link.
- `--version` CLI flag.

### Changed

- `install.sh` now explicitly detects an existing installation and prints an update message before overwriting.
- Removed the post-hashing integrity footer append so the report SHA-256 always matches the final signed file.

## [0.1.0] - Initial release

- Interactive directory documentation with recursive listing, file sizes, modification times, and MD5/SHA-256/SHA-512 hashes.
- Optional detached GPG signature.
