# ReplayShield-PAM

ReplayShield is a lightweight HTTP authentication service that protects PAM (e.g. SSH) by rejecting recently used passwords. It stores per-user password pools, tracks the most recent usages, and blocks any password that falls within a configurable “recently used” window.

## Features

- Encrypted SQLite database stored at rest and decrypted only inside `/dev/shm`.
- HTTP POST `/auth` endpoint that validates a username/password pair and returns `PASS` or `FAIL`.
- PAM integration via `pam_exec.so` script (`/usr/lib/replayshield/replayshield-pam.sh`).
- Systemd service file and Debian packaging scripts included.

## Building

Requirements:

- JDK 21
- Gradle (wrapper included)

```bash
./gradlew clean shadowJar
```

The runnable JAR is created at `build/libs/replayshield.jar`.

## Running the Server

ReplayShield needs a cached admin key in `/dev/shm/replayshield/admin.key` before the HTTP server can start.

```bash
sudo ./gradlew run --args='password'   # cache admin password in RAM
sudo ./gradlew run --args='serve'      # start HTTP server on 127.0.0.1:4444
```

Create users and manage password pools via:

```bash
sudo ./gradlew run --args='manage'
```

## PAM Integration

1. Ensure the ReplayShield service is running and the admin key cache is present.
2. Add the following line to the desired PAM policy (for example `/etc/pam.d/sshd`):
   ```
   auth required pam_exec.so expose_authtok /usr/lib/replayshield/replayshield-pam.sh
   ```
3. The script reads the username (`PAM_USER`) and password from PAM, posts them to `http://127.0.0.1:4444/auth`, and expects `PASS` to allow authentication.

## Debian Packaging

Use the helper script to build a `.deb` that bundles the JAR, wrapper scripts, PAM helper, and systemd unit. Build artifacts are moved into `release/` under the project root.

```bash
./packaging/build-deb.sh
sudo dpkg -i release/replayshield_*.deb
```

During installation the post-install script will remind you to:

1. Run `sudo replayshield password && sudo systemctl start replayshield`.
2. Update your PAM policy with the `pam_exec` line shown above.

All packaging assets (Debian metadata, PAM helper, systemd unit, build script) live under the `packaging/` directory. The build script temporarily copies `packaging/debian` to the repository root when invoking `dpkg-buildpackage`, then moves the resulting `.deb`, `.buildinfo`, and `.changes` files into `release/`.

## Repository Structure

| Path | Description |
| --- | --- |
| `src/main/java` | ReplayShield application code |
| `packaging/systemd/replayshield.service` | systemd unit for the HTTP server |
| `packaging/replayshield-pam.sh` | PAM helper script executed by `pam_exec.so` |
| `packaging/replayshield.sh` | `/usr/bin/replayshield` wrapper |
| `packaging/build-deb.sh` | Convenience script to build the Debian package |
| `packaging/debian` | Debian packaging metadata |

## License

MIT License. See `LICENSE` for details.
