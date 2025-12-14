# ReplayShield-PAM

ReplayShield is a lightweight HTTP authentication service that rejects recently used passwords during PAM (for example SSH) logins to mitigate password-reuse attacks. It keeps a per-user password pool and history, blocking any credential that falls within the configured `block_count` window.

[한국어 README](README_KR.md)

## Key Features

- CLI workflow via `replayshield init/manage/password/serve`:
  - **init** – Initialization  
    Prompts for an admin password and creates an encrypted database with that key. Re-running overwrites the existing DB (re-initialization).
  - **manage** – Manage users/password pools  
    - *Add new user*: create a user and register initial passwords.  
    - *Manage user*: add/delete passwords, adjust block counts per user.  
    - *Delete user*: remove a user entirely.  
    - *Change admin password*: rotate the admin key.  
    - *DB dump*: print the current database (users/password history) to the console.
  - **password** – Cache the admin key  
    Stores the admin credential in tmpfs so `replayshield serve` can start in a headless environment.
  - **serve** – Run the authentication server  
    Uses the cached admin key to launch the HTTP server.

- Encrypted SQLite DB: data is always encrypted on disk and decrypted only inside `/dev/shm`.
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
   Add ReplayShield to `/etc/pam.d/sshd` (or your target PAM policy):
   ```
   auth required pam_exec.so quiet expose_authtok /usr/lib/replayshield/replayshield-pam.sh
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
   sudo replayshield init      # creates salt and encrypted DB; running again resets everything
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

## License

Apache License 2.0 (`LICENSE`).  
You may use, modify, and redistribute the project in source or binary form as long as:
- a copy of the Apache 2.0 license (and any NOTICE text) accompanies your distribution,
- modified files include a notice describing the changes, and
- attribution/copyright notices are preserved.

The software is provided “as is,” without warranties or conditions of any kind.
