# Changelog

All notable changes to this project are documented in this file.

## [0.3.1] - 2026-02-11

### Added
- `replayshield-login-notify.sh` helper script for login-time service-status banner checks.

### Changed
- `replayshield.service` now includes `[Install]` metadata (`WantedBy=multi-user.target`) for normal `systemctl enable` behavior.
- Debian maintainer scripts now guard systemd commands in non-systemd environments.
- Packaging script layout was reorganized (`packaging/package-scripts/`) to separate build tooling from package payload scripts.
- PAM hook documentation and examples now consistently use `/usr/lib/replayshield/*` paths.
- Project version updated to `0.3.1`.

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
