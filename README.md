# ReplayShield-PAM

ReplayShield is a lightweight HTTP authentication service that augments PAM (for example SSH) by rejecting passwords that were recently used. It stores a per-user password pool, keeps usage history, and blocks any password that falls inside a configurable window.

## Features

- CLI workflow (`replayshield init/manage/password/serve`) for bootstrapping, managing password pools, caching the admin key, and running the HTTP auth server.
- Per-user password history with hints, hit counters, block state, and automatic enforcement of a `block_count` window.
- Encrypted SQLite database: data stays encrypted on disk and only exists in clear form inside `/dev/shm`.
- HTTP POST `/auth` endpoint returning `PASS`/`FAIL` for PAM helpers.
- PAM integration script (`/usr/lib/replayshield/replayshield-pam.sh`) compatible with `pam_exec.so expose_authtok` and additional factors such as Google Authenticator.
- Systemd service unit, Debian packaging scripts, and wrapper binaries for `/usr/bin/replayshield`.

## Installation

### Build from source

Requirements: JDK 21 and the Gradle wrapper in this repo.

```bash
./gradlew clean shadowJar
```

The runnable JAR will be available under `build/libs/replayshield.jar`.

### Debian package

Use the helper to create a `.deb` that contains the JAR, PAM helper, wrapper, and systemd unit.

```bash
./packaging/build-deb.sh
sudo dpkg -i release/replayshield_*.deb
```

After installation `replayshield` is available in `/usr/bin`, the PAM script is placed under `/usr/lib/replayshield`, and a `replayshield.service` unit is installed but inactive until configured.
The package also installs a bash-completion script under `/usr/share/bash-completion/completions/replayshield`, so typing `replayshield <TAB>` suggests `init`, `manage`, `password`, and `serve`.

## Configuration

1. **PAM policy**
   - Edit `/etc/pam.d/sshd` (or any other target PAM stack) and insert the ReplayShield hook:
     ```
     auth required pam_exec.so quiet expose_authtok /usr/lib/replayshield/replayshield-pam.sh
     ```
   - Keep or re-enable any necessary `@include common-auth`, `common-account`, and `common-session` lines so standard system checks still run alongside ReplayShield.
   - Optional: place other modules (e.g. Google Authenticator) before/after the ReplayShield line. A common pattern is:
     ```
     auth [success=1 default=ignore] pam_succeed_if.so user = guest1
     auth required pam_google_authenticator.so
     ```
2. **Systemd**
   - Adjust `/etc/default/replayshield` or the unit override if you need to change the listening address/port (default `127.0.0.1:4444`) or environment variables like `REPLAYSHIELD_URL` for the PAM script.
3. **Filesystem prerequisites**
   - Ensure `/dev/shm` is mounted as tmpfs (required for decrypted database files).
   - Confirm `/etc/replayshield` and `/var/lib/replayshield` exist with root-only permissions; the installer creates them but you can verify with `sudo ls -ld`.

## Running

1. **Initialize or manage data**
   - `sudo replayshield init` creates the salt file and encrypted database. Re-run only if you intend to wipe all stored data.
   - `sudo replayshield manage` launches the interactive CLI for creating users, managing password pools, adjusting `block_count`, and dumping debug tables (which now use the new ASCII table renderer).
2. **Cache the admin password**
   - The HTTP server requires the admin key to be present in `/dev/shm/replayshield/admin.key`.
   - Run `sudo replayshield password` (or `sudo ./gradlew run --args='password'` during development) and follow the prompt. This stores the key in RAM until reboot.
3. **Start the service**
   - For ad-hoc testing: `sudo replayshield serve` or `sudo ./gradlew run --args='serve'`.
   - For systemd: `sudo systemctl enable --now replayshield`. Ensure step 2 has been completed before the service starts.
4. **Verify PAM flow**
   - Attempt an SSH login. ReplayShield’s PAM helper posts the username/password to `http://127.0.0.1:4444/auth` and expects `PASS`. `FAIL` or errors cause the PAM transaction to abort.

## Repository Structure

| Path | Description |
| --- | --- |
| `src/main/java` | ReplayShield application code |
| `packaging/systemd/replayshield.service` | systemd unit used by the `.deb` |
| `packaging/replayshield-pam.sh` | PAM helper executed by `pam_exec.so` |
| `packaging/replayshield.sh` | `/usr/bin/replayshield` wrapper script |
| `packaging/build-deb.sh` | Convenience script that runs `dpkg-buildpackage` |
| `packaging/debian` | Debian metadata (control, rules, postinst/postrm, etc.) |

## License

MIT License. See `LICENSE` for details.
