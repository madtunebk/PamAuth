use anyhow::Result;
use pin_auth::verify_pin;
use std::env;
use std::fs;
use std::io::{self, Read};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
#[cfg(feature = "syslog")]
use syslog::{Facility, Formatter3164};

// Exit codes
const EXIT_OK: i32 = 0;          // success
const EXIT_MISMATCH: i32 = 1;    // wrong pin / generic failure
const EXIT_LOCKED: i32 = 2;      // locked out
const EXIT_INPUT: i32 = 3;       // bad input format / empty
const EXIT_CONFIG: i32 = 4;      // config error (length policy, etc.)

fn main() -> Result<()> {
    let user = env::var("PAM_USER")
        .or_else(|_| env::var("USER"))
        .unwrap_or_default();
    if user.is_empty() {
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

    let base_dir = env::var("PIN_DIR").unwrap_or_else(|_| "/etc/pin.d".to_string());
    let path = format!("{}/{}.passwd", base_dir, user);
    let stored = match fs::read_to_string(&path) {
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
    if let Ok(raw) = fs::read_to_string(&fail_file) {
        let line = raw.trim();
        if let Some(rest) = line.strip_prefix("lock:") {
            if let Ok(until) = rest.parse::<u64>() {
                if now < until {
                    // still locked
                    #[cfg(feature = "syslog")]
                    if let Some(ref mut l) = logger { let _ = l.err(format!("pin-auth: user={user} locked (until {until})")); }
                    std::process::exit(EXIT_LOCKED);
                } else {
                    // lock expired; reset
                    let _ = fs::remove_file(&fail_file);
                }
            } else {
                // malformed; ignore
                let _ = fs::remove_file(&fail_file);
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
            // ensure lock file state
            let until = now.saturating_add(lockout_secs);
            let _ = fs::write(&fail_file, format!("lock:{}\n", until));
        }
    #[cfg(feature = "syslog")]
    if let Some(ref mut l) = logger { let _ = l.err(format!("pin-auth: user={user} locked (threshold reached)")); }
    std::process::exit(EXIT_LOCKED);
    }

    let mut input = String::new();
    io::stdin().read_to_string(&mut input).ok();
    let mut candidate = input.trim_end_matches('\n').to_string();
    if candidate.is_empty() {
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
    std::process::exit(EXIT_INPUT);
    }

    if verify_pin(&mut candidate, &stored) {
        // success → reset fail counter / lock
    let _ = fs::remove_file(&fail_file);
    #[cfg(feature = "syslog")]
    if let Some(ref mut l) = logger { let _ = l.info(format!("pin-auth: user={user} success")); }
    std::process::exit(EXIT_OK);
    } else {
        fail_count += 1;
        if fail_count >= max_fails {
            if lockout_secs > 0 {
                let until = now.saturating_add(lockout_secs);
                let _ = fs::write(&fail_file, format!("lock:{}\n", until));
            } else {
                let _ = fs::write(&fail_file, format!("{}:{}\n", fail_count, first_ts));
            }
        } else {
            let _ = fs::write(&fail_file, format!("{}:{}\n", fail_count, first_ts));
        }
        #[cfg(feature = "syslog")]
    if let Some(ref mut l) = logger { let _ = l.warning(format!("pin-auth: user={user} failure count={fail_count}")); }
        if fail_count >= max_fails { std::process::exit(EXIT_LOCKED); }
        std::process::exit(EXIT_MISMATCH);
    }
}
