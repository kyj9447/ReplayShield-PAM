# ReplayShield-PAM

ReplayShield is a lightweight HTTP authentication service that rejects recently used passwords during PAM (for example SSH) logins to mitigate password-reuse attacks. It keeps a per-user password pool and history, blocking any credential that falls within the configured `block_count` window.

[한국어 README](README_KR.md)

## Key Features

- CLI workflow via `replayshield init/manage/password/serve/benchmark`:
  - **init** – Initialization  
    Prompts for an admin password, writes salt/admin marker, and initializes the encrypted per-user DB directory. Re-running resets all stored users (re-initialization).
  - **manage** – Manage users/password pools  
    - *Add new user*: create a user and register initial passwords.  
    - *Manage user*: add/delete passwords, adjust block counts per user.  
    - *Delete user*: remove a user entirely.  
    - *Change admin password*: rotate the admin key.  
    - *DB dump*: print all user DB snapshots (config/pool/history) to the console.
  - **password** – Cache the admin key  
    Stores the admin credential in tmpfs so `replayshield serve` can start in a headless environment.
  - **serve** – Run the authentication server  
    Uses the cached admin key to launch the HTTP server.
  - **benchmark** – Run DB benchmark  
    Runs side-by-side comparison of `single-db` and `per-user-db` modes on isolated temporary benchmark DB files.
    Each mode uses the same password-pool size (100 per user), fixed traffic profile (`--target-rps`, `--measure-seconds`), and alternating execution order.
    User-scale sweep is configurable via `--users-list` (default `1,10,100`) or `--users=<N>` for a single scenario.
    Per-user mode also includes directory-scan lookup cost, reported as `lookup` in the benchmark output.
    No admin password prompt is required; CLI prints the default benchmark login (`bench_u0` / `bench_u0_pw0_Aa1!`).

- Encrypted SQLite DB: each user has a dedicated encrypted DB file under `/var/lib/replayshield/users/*.db.enc`; data is decrypted only inside `/dev/shm`.
- This per-user split removes the single-DB scaling bottleneck where auth workload grew linearly with total user count.
- `/auth` HTTP POST endpoint returns `PASS`/`FAIL`, and the PAM helper consumes this result to decide login flow.
- PAM helper script (`/usr/lib/replayshield/replayshield-pam.sh`) integrates with `pam_exec.so expose_authtok`.

## 1. Installation

Prerequisite: JDK 21.

If you already have a `.deb` package (from GitHub Releases or `packaging/build-deb.sh`):

```bash
sudo dpkg -i replayshield_*.deb
```

## 2. Configuration

1. **PAM configuration**  
   Add both ReplayShield PAM hooks:
   - Add this auth hook to `/etc/pam.d/sshd` (or your target PAM policy):
   ```
   auth required pam_exec.so quiet expose_authtok /usr/lib/replayshield/replayshield-pam.sh
   ```
   - Add this session hook to both `/etc/pam.d/sshd` and `/etc/pam.d/login`:
   ```
   session optional pam_exec.so /usr/lib/replayshield/replayshield-login-notify.sh
   ```
   If you have deliberately replaced the default Unix password auth, comment out the relevant `@include common-...` lines:
   ```
   # @include common-auth
   # @include common-account
   # @include common-session
   ```
   Add other modules (e.g., Google Authenticator) before/after the ReplayShield line as needed.

2. **Filesystem check**  
   Ensure `/dev/shm` is mounted as tmpfs:
   ```bash
   mount | grep /dev/shm
   ```
   You should see something like:
   ```
   tmpfs on /dev/shm type tmpfs (rw,nosuid,nodev,inode64)
   ```

## 3. Running

1. **Initialization & management**
   ```bash
   sudo replayshield init      # creates salt/marker and encrypted per-user DB storage; running again resets everything
   sudo replayshield manage    # manage users/password pools, adjust block_count, run DB dumps, etc.
   ```

2. **Cache the admin password**
   ```bash
   sudo replayshield password
   ```
   This stores the admin key in `/dev/shm/replayshield/admin.key`.

3. **Start the service**
   ```bash
   sudo systemctl start replayshield
   ```
   The daemon deletes the cached key once it starts successfully, so if you restart the service you must run `replayshield password` again before `systemctl restart`.

4. **Verify PAM flow**  
   Try an SSH login. The PAM script posts the username/password to `http://127.0.0.1:4444/auth` and only continues if it receives `PASS`.

5. **Run benchmark comparison**
   ```bash
   sudo replayshield benchmark --warmup-seconds=5 --measure-seconds=30 --target-rps=100 --users-list=1,10,100
   ```
   This runs `single-db`/`per-user-db` under identical traffic for each user-count scenario and prints scaling comparisons.

## License

Apache License 2.0 (`LICENSE`).  
You may use, modify, and redistribute the project in source or binary form as long as:
- a copy of the Apache 2.0 license (and any NOTICE text) accompanies your distribution,
- modified files include a notice describing the changes, and
- attribution/copyright notices are preserved.

The software is provided “as is,” without warranties or conditions of any kind.
