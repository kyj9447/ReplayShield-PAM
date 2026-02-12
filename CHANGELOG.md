# Changelog

All notable changes to this project are documented in this file.

## [0.5.0] - 2026-02-12

### Changed
- Benchmark output now includes `min` and `max` metrics in addition to `avg` and `median` for both single-db and per-user-db modes.
- `BENCH_RESULT` machine-readable format was expanded to include `min`/`max` fields, and parent-side parsing/summary output was updated accordingly.
- Benchmark iteration result counting was simplified into a single `switch` block.
- Project version updated to `0.5.0`.

## [0.4.0] - 2026-02-11

### Changed
- Authentication storage layout moved from a single encrypted DB to per-user encrypted DB files under `/var/lib/replayshield/users/*.db.enc`.
- Authentication flow now opens only the target user's encrypted DB file, reducing user-count-proportional overhead from scanning a shared DB.
- `manage` CLI operations were updated to use per-user DB files (create/manage/delete/dump).
- Admin key verification now uses an admin marker file (`/var/lib/replayshield/admin.marker`).
- Benchmark compare mode now runs user-scale sweeps (`--users-list`, default `1,10,100`) with fixed traffic profile (`--target-rps`, `--measure-seconds`), alternating mode order, 100 passwords per user, and explicit per-user directory-scan lookup measurement (`lookup`).
- Project version updated to `0.4.0`.

## [0.3.1] - 2026-02-11

### Added
- `replayshield-login-notify.sh` helper script for login-time service-status banner checks.

### Changed
- `replayshield.service` now includes `[Install]` metadata (`WantedBy=multi-user.target`) for normal `systemctl enable` behavior.
- Debian maintainer scripts now guard systemd commands in non-systemd environments.
- Packaging script layout was reorganized (`packaging/package-scripts/`) to separate build tooling from package payload scripts.
- PAM hook documentation and examples now consistently use `/usr/lib/replayshield/*` paths.
- Removed benchmark actual-DB mode; benchmark now always runs on an isolated temporary DB.
- Benchmark mock dataset now seeds 10 users with 100 passwords each (1000 tuples total).
- Default benchmark measured iterations increased from 50 to 500.
- Benchmark no longer prompts for ReplayShield admin password and now prints default test login credentials in CLI.
- Project version updated to `0.3.1`.

## [0.3.0] - 2026-02-10

### Added
- `benchmark` CLI command to measure authentication flow performance.
- Benchmark options for configurable warmup/iterations.

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
