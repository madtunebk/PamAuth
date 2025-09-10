# pin-auth

Minimal helper utilities to bolt on a short PIN (or other short secret) check inside a PAM (Pluggable Authentication Modules) stack via `pam_exec`.

> ⚠️ **SECURITY WARNING (READ FIRST)**  
> This is **not** a full multi‑factor solution. A PIN entered in the same password prompt is *just another shared secret* and is vulnerable to brute force if rate limiting is weak. Treat it like a *short alternate password*. Audit, harden, and consider using established MFA solutions for real security requirements.

## Why Would I Use This?
Lightweight situations where you want a *small* extra gate without writing a full PAM module:
* Kiosk / lab / maker device quick unlock PIN.
* Temporary alternate short credential for a throwaway account.
* Demo / teaching example of integrating a custom verifier with PAM.

## Do NOT Use This For
* Strong MFA (it isn’t: same channel, same prompt).
* Protecting high‑value production systems against determined attackers.
* Any environment where regulatory / compliance requirements mandate audited auth modules.

## Binaries
* `genpin` – create/update a hashed PIN in `/etc/pin.d/<user>.passwd`.
* `check_pin` – verify a candidate (from stdin) against the stored hash; returns structured exit codes.

## Feature Highlights
* Pure Rust hashing backends: SHA‑512 crypt (default) or Argon2id (optional feature).
* Optional Argon2 cost tuning via environment.
* Per‑user fail counter + timed lockout (pam_faillock‑like).
* Non‑interactive provisioning for automation.
* Digit length policy (min / max) enforced at set & verify time.
* Structured exit codes for better PAM scripting / logging.
* Optional syslog logging (feature `syslog`).
* Fixed secure directory: `/etc/pin.d` (override only in debug/test builds, not in release binaries).

## Quick Start
```bash
cargo build --release
sudo install -D -m 0755 target/release/genpin /usr/local/sbin/genpin
sudo install -D -m 4755 target/release/check_pin /usr/local/sbin/check_pin
sudo mkdir -p /etc/pin.d && sudo chmod 700 /etc/pin.d

sudo genpin alice   # set a PIN (default policy 4..6 digits)
echo 1234 | PAM_USER=alice /usr/local/sbin/check_pin && echo OK || echo FAIL
```

Add to (for example) `/etc/pam.d/login` *before* normal password auth if you want fast success:
```
auth sufficient pam_exec.so expose_authtok quiet /usr/local/sbin/check_pin
```
Or use `required` if the PIN must also succeed.

## Build
Rust 1.70+ (Edition 2021). No external libcrypt needed.
```bash
cargo build --release
```

## Install

Copy the binaries to a root-owned directory in PATH (e.g. `/usr/local/sbin`). Make `check_pin` setuid root so it can read the protected PIN directory; `genpin` does not need to be setuid (you typically run it with sudo when writing `/etc/pin.d`).

```bash
sudo install -D -m 0755 target/release/genpin /usr/local/sbin/genpin
sudo install -D -m 4755 target/release/check_pin /usr/local/sbin/check_pin
```

Create the storage directory (root only, 0700):

```bash
sudo mkdir -p /etc/pin.d
sudo chmod 700 /etc/pin.d
```

## Setting / Updating a PIN

Run (as root or with sudo so ownership/permissions can be enforced):

```bash
sudo genpin alice
# Prompts:
# Enter new PIN:
# Repeat new PIN:
```

A file will be written at `/etc/pin.d/alice.passwd` with mode 0600 and owner root:root containing a `$6$` (SHA-512 crypt) hash (or Argon2 if configured at build/runtime).

Policy (defaults can be changed with env vars):
* Digits only (0-9). Any non-digit input is rejected.
* Default minimum length: 4 (override with `PIN_MIN_LEN`).
* Default maximum length: 6 (override with `PIN_MAX_LEN`).
* `PIN_MAX_LEN` must be >= `PIN_MIN_LEN`.
* These limits are enforced both when generating and verifying (defense in depth).

The storage directory is fixed at `/etc/pin.d` for release builds. In debug/test builds (e.g. during `cargo test`) an environment variable `PIN_DIR` may be used internally to isolate test data; this is intentionally ignored in optimized release binaries to prevent environment-based redirection attacks.

### Non-interactive Mode

For scripting (CI/tests/automation) you can supply the PIN via the `GENPIN_NONINTERACTIVE` environment variable instead of using TTY prompts:

```bash
GENPIN_NONINTERACTIVE=2468 ./target/release/genpin alice
```

You can optionally include a confirmation (otherwise it reuses the same value):

```bash
GENPIN_NONINTERACTIVE=2468:2468 ./target/release/genpin alice
```

If you call `genpin` without a username it performs a no-op and exits success (useful when templating commands that may or may not have a user variable set); no files are created.

## Manual Verification (Debug)

You can test `check_pin` outside PAM by piping a candidate PIN on stdin and setting `PAM_USER`:

```bash
echo 1234 | PAM_USER=alice ./target/release/check_pin && echo OK || echo FAIL
```

Exit status 0 means match.

## PAM Integration Details

Add a line using `pam_exec.so` referencing `check_pin`. Placement depends on whether the PIN should be sufficient by itself or an additional factor. Example for login (`/etc/pam.d/login`) adding it as an *sufficient* auth method before the normal password:

```
# PIN auth (if present) – succeed fast if PIN matches
auth    sufficient    pam_exec.so expose_authtok seteuid quiet /usr/local/sbin/check_pin
# (Rest of your normal auth stack below)
```

Explanation of options:

* `expose_authtok` – Passes the user's entered password/PIN to the helper on stdin.
* `seteuid` – Runs the helper with the effective UID (needed for setuid binary semantics reliability). Often optional here but common with pam_exec.
* `quiet` – Suppresses extra messages.

If you want the PIN to be *required* in addition to the main password, change `sufficient` to `required` and place it early; the user must then enter the PIN in the password prompt (and your primary module must still succeed).

Because both factors are typed into the *same* single password prompt in this simple design, this mainly acts as a per-user alternate short password. For true multi-factor separation (different prompts/devices), a more advanced module or challenge mechanism is required.

## Security Notes & Threat Model

* Hashing: Uses SHA-512 crypt (`$6$`) (default) or Argon2id if enabled (`PIN_SCHEME=argon2`). For stronger resistance or higher cost tune Argon2 parameters.
* PIN length & format: Configurable via `PIN_MIN_LEN` (default 4) and `PIN_MAX_LEN` (default 6); only digits allowed to keep semantics clear.
* Short secrets (PINs) are vulnerable to brute force; rate limiting must occur elsewhere (e.g. `pam_faillock`, `pam_tally2`, or host-based protections). This helper does not implement throttling.
* Files are root-owned and 0600 to prevent unprivileged reads. Ensure backups/logs do not leak them.
* `check_pin` being setuid root increases audit needs; keep the code small (as here) and prefer regular security hardening: `nosuid` mounts, file integrity monitoring, etc.
* PIN strings used for hashing/verification are zeroized after use in memory, but process memory should still be considered sensitive while running.
* Built-in lockout: per-user `.fail` file with threshold (`PIN_MAX_FAILS`), window (`PIN_FAIL_WINDOW`, default 900s) & lock duration (`PIN_LOCKOUT_SECS`, default 300s). Locked state stored as `lock:<until_epoch>`.
* Exit codes: 0 success | 1 mismatch | 2 locked | 3 bad input | 4 config error.
* Optional syslog (feature `syslog`): logs success / failure / lock events (facility: AUTH).
* Argon2 recommended when strong memory hardness desired (enable `--features argon2` and set costs).
* This does NOT protect against credential interception (same prompt) or offline dictionary if hash files leak; ensure directory permissions and backups hygiene.

## Configuration Variants / Examples

Require a PIN only for specific users (e.g. members of a group) by wrapping logic in a tiny shell script or adjusting PAM conditionally (e.g., using `pam_succeed_if`). Simpler: only create `/etc/pin.d/<user>.passwd` for accounts you want protected; absence silently fails and PAM continues.

## Uninstall

```bash
sudo rm -f /usr/local/sbin/{genpin,check_pin}
# Optionally keep or remove stored PIN hashes
# sudo rm -rf /etc/pin.d
```

## Development & Testing

```bash
cargo fmt -- --check
cargo clippy --all-targets -- -D warnings
cargo build
cargo test
```

Run both binaries with `RUST_BACKTRACE=1` for debugging on unexpected failures.

### Environment Variables

| Variable | Purpose | Default |
|----------|---------|---------|
| (fixed) | Directory storing `<user>.passwd` (+ optional `<user>.fail`) | `/etc/pin.d` |
| `GENPIN_NONINTERACTIVE` | Provide PIN (or `PIN:CONFIRM`) non-interactively to `genpin` | unset (interactive) |
| `PIN_SCHEME` | Hashing scheme: `argon2`/`argon2id` (if argon2 feature enabled) or `sha-crypt` | `sha-crypt` (build default) |
| `PIN_MIN_LEN` | Minimum allowed PIN length | `4` |
| `PIN_MAX_LEN` | Maximum allowed PIN length | `6` |
| `PIN_MAX_FAILS` | Lockout threshold for `check_pin` attempts (stored in `<user>.fail`) | `5` |
| `PIN_FAIL_WINDOW` | Time window in seconds to accumulate failures before reset (0 = no reset) | `900` |
| `PIN_LOCKOUT_SECS` | Seconds to lock after threshold reached (0 = permanent until manual reset/new PIN) | `300` |
| `PIN_ARGON2_M_COST` | Argon2 memory cost (KiB) (all 3 must be set) | backend default |
| `PIN_ARGON2_T_COST` | Argon2 iterations (time cost) | backend default |
| `PIN_ARGON2_P_COST` | Argon2 parallelism | backend default |
| `PIN_SYSLOG_FAIL_SAMPLE` | Log only every Nth failure (1 = log all) | `1` |

Behavior notes:
* Absence of a hash file for a user makes `check_pin` fail (letting PAM continue to next module).
* Lockout occurs when failures >= `PIN_MAX_FAILS`; counter resets on successful auth or PIN regeneration.
* Timed lockouts: if `PIN_LOCKOUT_SECS>0` a lock record `lock:<until>` is written; after that epoch the file is removed automatically on next attempt.
* Argon2 parameters only applied if all three cost vars parse to >0. Example moderate settings: `PIN_ARGON2_M_COST=65536 PIN_ARGON2_T_COST=3 PIN_ARGON2_P_COST=1`.

## Hardening Checklist
* Enable Argon2 feature and tune costs appropriately.
* Add PAM rate limiting (`pam_faillock`) in addition to built-in lockout.
* Restrict `/etc/pin.d` to root (0700) – already required.
* Monitor syslog (if enabled) for unexpected spikes in failures / lockouts.
* Consider using distinct exit codes in PAM rules if chaining custom logic.
* Keep the code small & audited; rebuild on security updates.

## CI / Quality
GitHub Actions workflow runs fmt, clippy (warnings as errors), tests across feature matrices including Argon2 + syslog.
* Running `genpin` with no username exits 0 and does nothing.

## Roadmap / Ideas

* Bcrypt / scrypt optional backends.
* Distinct backoff (progressive delays) instead of immediate lock.
* Custom PAM module for separate prompt (true second factor UX).
* Optional JSON audit log to file.
* Systemd notification / journald structured fields.

## License

MIT (see `LICENSE`).

---

Happy hacking.
