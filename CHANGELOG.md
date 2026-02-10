# Changelog

All notable changes to this project are documented in this file.

## [0.3.0] - 2026-02-10

### Added
- `benchmark` CLI command to measure authentication flow performance.
- `benchmark --mode=actual` for real DB authentication flow measurement.
- `benchmark --mode=test` for isolated temporary mock DB benchmark.

### Changed
- Benchmark output now reports end-to-end, decrypt, auth-logic, and encrypt timing summaries.
- Test benchmark mock dataset now seeds 100 passwords for `bench_user`.
- Project version updated to `0.3.0`.

## [0.2.0] - 2025-12-14

### Added
- Debian package release `0.2.0`.

## [0.1.0] - 2025-12-13

### Added
- Initial Debian packaging for ReplayShield PAM HTTP auth server.
