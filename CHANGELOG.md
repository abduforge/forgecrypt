# Changelog

All notable changes to ForgeCrypt are documented here.

## [2.0.0] - GLOBAL

### Added
- Streaming format v2 for large regular files, processed in 1 MiB chunks.
- Per-record XChaCha20-Poly1305 authentication with a fresh OS-generated 24-byte nonce per record.
- Authenticated final record binding the final sequence number and total plaintext length, detecting truncation.
- Streaming `encrypt`, `decrypt`, `verify`, and `rekey` CLI operations.
- Bounded in-memory re-key pipeline; no intermediate plaintext file is written for format v2.
- Staged private outputs; CLI publishes destination files only after successful completion and never overwrites existing paths.
- Backward reading, verification, inspection, and re-key support for legacy format v1 files.
- `doctor` command and expanded English/Russian documentation.
- GitHub release workflow for Linux x86_64 archives.

### Changed
- New encryptions now use container format v2.
- Version output identifies the GLOBAL release.
- README starts with a direct latest-release download link and a short quick-start guide.

### Security notes
- No independent security audit has been performed.
- Format v1 remains limited to 16 MiB and uses the legacy in-memory implementation.
- Format v2 is experimental until independently reviewed.
