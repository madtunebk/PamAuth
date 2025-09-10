# pin-auth

Minimal helper utilities to enforce a short per-user PIN (or other short secret) inside a PAM stack via `pam_exec`.

> ⚠️ **SECURITY WARNING**  
> This is **not** real multi‑factor auth. The PIN is entered in the *same* password prompt and is just another shared secret. Use only where a lightweight extra gate is acceptable.

---
## Table of Contents
1. Rationale & Non‑Goals  
2. Features at a Glance  
3. Quick Start (Build, Install, First PIN)  
4. PAM Integration (sufficient vs required)  
5. PIN Policy & Non‑Interactive Provisioning  
6. Environment Variables  
7. Security Model & Threat Notes  
8. Built‑in Lockout & Logging  
9. Hardening Checklist  
10. Development  
11. Configuration Variants  
12. Roadmap  
13. License

---
## 1. Rationale & Non‑Goals
Use cases:
* Kiosk / lab / maker device quick unlock.
* Throwaway / demo account alternate short secret.
* Teaching example of PAM + external helper.

Do **not** use for:
* Strong MFA (single prompt = single factor).
* High‑value production systems with determined adversaries.
* Regulated environments needing audited/authenticated PAM modules.

## 2. Features at a Glance
* Pure Rust hashing: SHA‑512 crypt (default) or Argon2id (feature `argon2`).
* Argon2 cost tuning via env vars.
* Per‑user fail counter with window + timed lockout.
* Digit length policy (min/max) enforced at set & verify.
* Structured exit codes (0 ok | 1 mismatch | 2 locked | 3 bad input | 4 config).
* Optional syslog logging (feature `syslog`) with failure sampling.
* Zeroization of PIN buffers after use.
* Fixed secure directory: `/etc/pin.d` (release) – debug/tests may override internally.

## 3. Quick Start
```bash
cargo build --release
sudo install -D -m 0755 target/release/genpin /usr/local/sbin/genpin
sudo install -D -m 4755 target/release/check_pin /usr/local/sbin/check_pin
sudo mkdir -p /etc/pin.d && sudo chmod 700 /etc/pin.d

sudo genpin alice          # interactively set a 4–6 digit PIN
echo 1234 | PAM_USER=alice /usr/local/sbin/check_pin && echo OK || echo FAIL
Root requirement: Both binaries expect effective UID 0 in release builds. This lets `check_pin` read protected files and ensures consistent ownership enforcement. For development/tests (debug builds) you can set `ALLOW_NON_ROOT=1` to bypass (used by the integration tests).
```

## 4. PAM Integration
Place the helper early in an auth stack using `pam_exec.so`.

Sufficient (PIN alone grants success; fallback to password if absent/mismatch):
```
auth  sufficient  pam_exec.so expose_authtok seteuid quiet /usr/local/sbin/check_pin
```

Required (PIN must succeed in addition to later password modules):
```
auth  required    pam_exec.so expose_authtok seteuid quiet /usr/local/sbin/check_pin
```
Options:
* `expose_authtok` – sends the typed secret to stdin of the helper.
* `seteuid` – ensures proper effective UID semantics for the setuid binary.
* `quiet` – suppress extra chatty output.

Because the PIN is typed in the same prompt, this behaves like an alternate short password. For real second‑factor UX use a dedicated PAM module with a separate challenge.

## 5. PIN Policy & Provisioning
Set / update a PIN:
```bash
sudo genpin alice
```
Policy (defaults modifiable via env):
* Digits only (0–9).
* Minimum length: `PIN_MIN_LEN` (default 4).
* Maximum length: `PIN_MAX_LEN` (default 6) and >= min.
* Enforced both at generation and verification.

Non‑interactive (automation / CI):
```bash
GENPIN_NONINTERACTIVE=2468 ./target/release/genpin alice
GENPIN_NONINTERACTIVE=2468:2468 ./target/release/genpin alice   # with explicit confirm
```
Calling `genpin` with no username is a no‑op (exit 0).

## 6. Environment Variables
| Variable | Purpose | Default |
|----------|---------|---------|
| (fixed) | Storage directory (release builds) | `/etc/pin.d` |
| `GENPIN_NONINTERACTIVE` | Provide `PIN` or `PIN:CONFIRM` non‑interactively | unset |
| `PIN_SCHEME` | `argon2` / `argon2id` / `sha-crypt` (feature dependent) | build default (`sha-crypt`) |
| `PIN_MIN_LEN` | Minimum PIN length | `4` |
| `PIN_MAX_LEN` | Maximum PIN length | `6` |
| `PIN_MAX_FAILS` | Fail threshold before lock | `5` |
| `PIN_FAIL_WINDOW` | Rolling window seconds to aggregate fails (0 = unlimited) | `900` |
| `PIN_LOCKOUT_SECS` | Lock duration after threshold (0 = indefinite until reset/new PIN) | `300` |
| `PIN_ARGON2_M_COST` | Argon2 memory KiB (all 3 Argon2 vars must be set) | backend default |
| `PIN_ARGON2_T_COST` | Argon2 iterations | backend default |
| `PIN_ARGON2_P_COST` | Argon2 parallelism | backend default |
| `PIN_SYSLOG_FAIL_SAMPLE` | Log only every Nth failure (1 = all) | `1` |

Behavior notes:
* No hash file ⇒ helper exits mismatch (PAM continues).
* Success or new PIN resets fail counter.
* Timed lockout writes `lock:<until_epoch>`; expires automatically.
* Argon2 tuning only applied if all three cost vars parse to >0 (e.g. `PIN_ARGON2_M_COST=65536 PIN_ARGON2_T_COST=3 PIN_ARGON2_P_COST=1`).

## 7. Security Model & Threat Notes
* Hashing: `$6$` (SHA‑512 crypt) by default; Argon2id optional.
* Short numeric space => brute force feasible: pair with host / PAM rate limiting.
* Setuid root binary kept minimal; review diffs regularly.
* Hash & fail files: root:root, 0600 inside directory 0700.
* PIN buffers zeroized after hashing / verification (still consider process memory sensitive while running).
* No protection against keylogging / credential interception in the shared prompt.
* Offline cracking risk if files leak; keep backups and logs secured.

## 8. Built‑in Lockout & Logging
* Fail state file `<user>.fail` stores either `count:first_ts` or `lock:<until>`.
* Window (`PIN_FAIL_WINDOW`) resets count after inactivity.
* Lock duration (`PIN_LOCKOUT_SECS`) controls automatic unlock time.
* Syslog (feature `syslog`): success, sampled failures, lock events (facility AUTH). Never logs PIN values.
* Sampling via `PIN_SYSLOG_FAIL_SAMPLE` reduces log flood during brute force.

## 9. Hardening Checklist
* Enable Argon2 (`--features argon2`) and tune costs.
* Add external PAM rate limiting (`pam_faillock`).
* Keep `/etc/pin.d` permissions strict (0700 dir, 0600 files).
* Monitor syslog for spikes & lockouts.
* Use distinct PAM control flags (`sufficient` vs `required`) intentionally.
* Rebuild with updates; audit setuid binary integrity.

## 10. Development
```bash
cargo fmt -- --check
cargo clippy --all-targets -- -D warnings
ALLOW_NON_ROOT=1 cargo test
```
Use `RUST_BACKTRACE=1` for troubleshooting. Integration tests run with a temporary debug override of the directory.

## 11. Configuration Variants
Selective enforcement: create hash files only for users needing a PIN; absence means fall through. Combine with `pam_succeed_if` or wrapper scripts to scope usage.

## 12. Roadmap / Ideas
* Bcrypt / scrypt optional backends.
* Progressive backoff instead of immediate lock.
* Dedicated PAM module for separate prompt (true 2nd factor UX).
* Optional JSON audit log.
* Systemd / journald structured logging.

## 13. License
MIT (see `LICENSE`).

---
Happy hacking.
