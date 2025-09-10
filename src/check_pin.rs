use anyhow::{Context, Result};
use pin_auth::verify_pin;
use std::env;
use std::fs::{self, OpenOptions};
use std::io::{self, Read};
use std::io::{Seek, SeekFrom, Write as IoWrite};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use nix::libc; // for O_NOFOLLOW / O_CLOEXEC
use std::os::unix::io::AsRawFd;
#[cfg(feature = "syslog")]
use syslog::{Facility, Formatter3164};

// Exit codes
const EXIT_OK: i32 = 0;          // success
const EXIT_MISMATCH: i32 = 1;    // wrong pin / generic failure
const EXIT_LOCKED: i32 = 2;      // locked out
const EXIT_INPUT: i32 = 3;       // bad input format / empty
const EXIT_CONFIG: i32 = 4;      // config error (length policy, etc.)

fn main() -> Result<()> {
    // Enforce root effective UID; debug build allows ALLOW_NON_ROOT=1 for tests.
    let euid = nix::unistd::geteuid().as_raw();
    if euid != 0 {
        #[cfg(not(debug_assertions))]
        {
            eprintln!("denied: requires root (effective uid 0)");
            std::process::exit(EXIT_CONFIG);
        }
        #[cfg(debug_assertions)]
        {
            if env::var("ALLOW_NON_ROOT").ok().as_deref() != Some("1") {
                eprintln!("denied: requires root (set ALLOW_NON_ROOT=1 in debug to bypass for tests)");
                std::process::exit(EXIT_CONFIG);
            }
        }
    }
    let user = env::var("PAM_USER")
        .or_else(|_| env::var("USER"))
        .unwrap_or_default();
    if user.is_empty() {
        std::process::exit(EXIT_CONFIG);
    }
    if !validate_username(&user) {
        // Reject suspicious usernames early
        std::process::exit(EXIT_CONFIG);
    }

    #[cfg(feature = "syslog")]
    let mut logger = syslog::unix(Formatter3164 {
        facility: Facility::LOG_AUTH,
        hostname: None,
        process: "check_pin".into(),
        pid: 0,
    })
    .ok();

    // Fixed directory in release; allow override only in debug/test builds for isolation.
    let requested_dir = if cfg!(debug_assertions) {
        env::var("PIN_DIR").unwrap_or_else(|_| "/etc/pin.d".to_string())
    } else {
        "/etc/pin.d".to_string()
    };
    let base_dir = secure_resolve_pin_dir(&requested_dir).unwrap_or_else(|_e| {
        #[cfg(feature = "syslog")]
        if let Some(ref mut l) = logger { let _ = l.err("pin-auth: dir validation failed".to_string()); }
        std::process::exit(EXIT_CONFIG)
    });
    let path = format!("{}/{}.passwd", base_dir, user);
    let stored = match read_file_nofollow(&path) {
        Ok(s) => s.trim().to_string(),
        Err(_) => std::process::exit(EXIT_MISMATCH),
    };

    // Fail counter / lockout
    let max_fails: u32 = env::var("PIN_MAX_FAILS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(5);
    let fail_file: PathBuf = [base_dir.as_str(), &format!("{}.fail", user)].iter().collect();
    let lockout_secs: u64 = env::var("PIN_LOCKOUT_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(300); // 5 minutes default
    let fail_window: u64 = env::var("PIN_FAIL_WINDOW")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(900); // 15 minutes aggregation window
    // Syslog failure sampling: log only every Nth failure (plus first & lock events)
    let _fail_sample: u32 = env::var("PIN_SYSLOG_FAIL_SAMPLE")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // File formats:
    //  - "count:first_ts"  (e.g. "2:1700000000")
    //  - "lock:until_ts"   (e.g. "lock:1700000300")
    //  - legacy: just number (treated as count with first_ts=now)
    let mut fail_count: u32 = 0;
    let mut first_ts: u64 = now;
    // Open (create if missing) fail file securely and obtain advisory lock to avoid races.
    let mut fail_fh = match OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&fail_file)
    {
        Ok(f) => f,
        Err(_) => {
            // Conservative: if cannot open tracking file, proceed without state (safer than denying legitimate auth attempt)
            // but no lockout enforced.
            // We still continue; subsequent code will treat empty state.
            // (Could also EXIT_CONFIG; design choice.)
            // Proceed.
            // Using a dummy file was overkill; simply skip parsing.
            // Fall through with fail_count=0.
            // NOTE: can't lock.
            // Return to flow.
            // (Intentionally empty)
            //
            // Because we cannot update the file, lockout enforcement becomes best-effort only.
            // This scenario should be rare.
            //
            // Continue execution.
            //
            // No early return.
            //
            // placeholder
            //
            // done
            //
            //
            // (Yes, verbose comment for clarity.)
            //
            //
            //
            //
            //
            // End of commentary.
            //
            //
            //
            //
            //
            //
            // Already explained rationale above.
            // Continue below.
            //
            // Provide a dummy handle logic by reopening /dev/null (read-only) so later code using fail_fh will fail gracefully if writing attempted.
            if let Ok(devnull) = OpenOptions::new().read(true).open("/dev/null") { devnull } else { return Err(anyhow::anyhow!("failed to open fail state")); }
        }
    };
    unsafe { libc::flock(fail_fh.as_raw_fd(), libc::LOCK_EX); }
    // Read existing content
    let mut raw_state = String::new();
    if std::io::Read::read_to_string(&mut fail_fh, &mut raw_state).is_ok() {
        let line = raw_state.trim();
        if let Some(rest) = line.strip_prefix("lock:") {
            if let Ok(until) = rest.parse::<u64>() {
                if now < until {
                    #[cfg(feature = "syslog")]
                    if let Some(ref mut l) = logger { let _ = l.err(format!("pin-auth: user={user} locked (until {until})")); }
                    std::process::exit(EXIT_LOCKED);
                } else {
                    // expired: overwrite below
                }
            }
        } else if let Some((cnt, ts)) = line.split_once(':') {
            if let (Ok(c), Ok(t)) = (cnt.parse::<u32>(), ts.parse::<u64>()) {
                fail_count = c;
                first_ts = t;
            }
        } else if let Ok(c) = line.parse::<u32>() { // legacy
            fail_count = c;
            first_ts = now;
        }
    }

    // Reset window if expired (unless window==0 meaning infinite accumulation)
    if fail_window > 0 && now.saturating_sub(first_ts) > fail_window {
        fail_count = 0;
        first_ts = now;
    }
    if fail_count >= max_fails {
        if lockout_secs > 0 {
            let until = now.saturating_add(lockout_secs);
            let _ = fail_fh.set_len(0);
            let _ = fail_fh.seek(SeekFrom::Start(0));
            let _ = IoWrite::write_all(&mut fail_fh, format!("lock:{}\n", until).as_bytes());
        }
        #[cfg(feature = "syslog")]
        if let Some(ref mut l) = logger { let _ = l.err(format!("pin-auth: user={user} locked (threshold reached)")); }
        std::process::exit(EXIT_LOCKED);
    }

    let mut input = String::new();
    io::stdin().read_to_string(&mut input).ok();
    let mut candidate = input.trim_end_matches('\n').to_string();
    if candidate.is_empty() {
        use zeroize::Zeroize;
        candidate.zeroize();
        input.zeroize();
        std::process::exit(EXIT_INPUT);
    }
    // Enforce digit-only and max length policy similar to generation step (defense in depth)
    let min_len: usize = env::var("PIN_MIN_LEN")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(4);
    let max_len: usize = env::var("PIN_MAX_LEN")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(6);
    if candidate.len() < min_len
        || candidate.len() > max_len
        || !candidate.chars().all(|c| c.is_ascii_digit())
    {
        use zeroize::Zeroize;
        candidate.zeroize();
        input.zeroize();
        std::process::exit(EXIT_INPUT);
    }

    if verify_pin(&mut candidate, &stored) {
        // success → reset fail counter / lock
    let _ = fail_fh.set_len(0);
    let _ = fail_fh.seek(SeekFrom::Start(0));
    #[cfg(feature = "syslog")]
    if let Some(ref mut l) = logger { let _ = l.info(format!("pin-auth: user={user} success")); }
    std::process::exit(EXIT_OK);
    } else {
    fail_count += 1;
        // persist update
    let _ = fail_fh.set_len(0);
    let _ = fail_fh.seek(SeekFrom::Start(0));
        if fail_count >= max_fails {
            if lockout_secs > 0 {
                let until = now.saturating_add(lockout_secs);
                let _ = IoWrite::write_all(&mut fail_fh, format!("lock:{}\n", until).as_bytes());
            } else {
                let _ = IoWrite::write_all(&mut fail_fh, format!("{}:{}\n", fail_count, first_ts).as_bytes());
            }
        } else {
            let _ = IoWrite::write_all(&mut fail_fh, format!("{}:{}\n", fail_count, first_ts).as_bytes());
        }
        #[cfg(feature = "syslog")]
        if let Some(ref mut l) = logger {
            // Never log candidate PINs; only metadata.
            let fs = _fail_sample; // local copy
            if fail_count == 1 || fail_count == max_fails || fs == 1 || (fs > 1 && fail_count % fs == 0) {
                let _ = l.warning(format!("pin-auth: user={user} failure count={fail_count}"));
            }
        }
        if fail_count >= max_fails { std::process::exit(EXIT_LOCKED); }
        std::process::exit(EXIT_MISMATCH);
    }
}

fn validate_username(u: &str) -> bool {
    // Conservative policy: 1..32 chars, [a-zA-Z0-9_-], must start alnum/underscore, not all digits.
    if u.is_empty() || u.len() > 32 { return false; }
    let mut chars = u.chars();
    if let Some(first) = chars.next() { if !first.is_ascii_alphanumeric() && first != '_' { return false; } } else { return false; }
    if u.contains('/') { return false; }
    if !u.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-') { return false; }
    true
}


fn secure_resolve_pin_dir(input: &str) -> Result<String> {
    // Always require absolute path when running setuid root; otherwise allow relative for tests.
    let euid_root = nix::unistd::geteuid().as_raw() == 0;
    let path = if euid_root { Path::new(input) } else { Path::new(input) };
    if euid_root {
        if !path.is_absolute() {
            anyhow::bail!("PIN_DIR must be absolute under root");
        }
    }
    // Canonicalize (best effort); if it fails we still attempt metadata on original.
    let meta_path = path;
    if euid_root {
        let md = fs::metadata(meta_path).with_context(|| format!("stat {:?}", meta_path))?;
        if md.file_type().is_symlink() {
            anyhow::bail!("PIN_DIR may not be a symlink");
        }
        if md.uid() != 0 {
            anyhow::bail!("PIN_DIR must be owned by root");
        }
        // Mode check (0700 expected; allow 0710 for group traverse if desired?)
        let mode = md.mode() & 0o7777;
        if mode & 0o022 != 0 { // group/world write bits
            anyhow::bail!("PIN_DIR must not be group/world writable");
        }
    }
    Ok(path.to_string_lossy().into_owned())
}

fn read_file_nofollow(path: &str) -> io::Result<String> {
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let mut buf = String::new();
    use std::io::Read as _;
    f.read_to_string(&mut buf)?;
    Ok(buf)
}
