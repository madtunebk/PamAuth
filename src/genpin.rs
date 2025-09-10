use anyhow::{bail, Context, Result};
use nix::unistd::{chown, Gid, Uid};
use pin_auth::hash_pin;
use rpassword::prompt_password;
use std::env;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

fn main() -> Result<()> {
    // Usage: genpin <username> [--dir /etc/pin.d]
    let mut args = env::args().skip(1);
    let user = if let Some(u) = args.next() {
        u
    } else {
        // No username supplied: silently do nothing (success exit)
        return Ok(());
    };
    let mut dir = std::env::var("PIN_DIR").unwrap_or_else(|_| "/etc/pin.d".to_string());
    if let Some(flag) = args.next() {
        if flag == "--dir" {
            dir = args.next().unwrap_or(dir);
        }
    }

    println!("Creating/Updating PIN for user: {user}");
    let non_interactive = std::env::var("GENPIN_NONINTERACTIVE").ok();
    let (pin1, pin2) = if let Some(val) = non_interactive {
        // Expect form PIN[:CONFIRM]; if only one provided reuse it.
        let mut parts = val.splitn(2, ':');
        let p1 = parts.next().unwrap().to_string();
        let p2 = parts.next().unwrap_or(&p1).to_string();
        (p1, p2)
    } else {
        let p1 = prompt_password("Enter new PIN: ")?;
        let p2 = prompt_password("Repeat new PIN: ")?;
        (p1, p2)
    };
    if pin1 != pin2 {
        bail!("PINs do not match");
    }
    let min_len: usize = std::env::var("PIN_MIN_LEN")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(4);
    let max_len: usize = std::env::var("PIN_MAX_LEN")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(6);
    if min_len == 0 || min_len > 32 {
        bail!("Unreasonable PIN_MIN_LEN");
    }
    if max_len < min_len {
        bail!("PIN_MAX_LEN ({max_len}) is less than PIN_MIN_LEN ({min_len})");
    }
    if pin1.len() < min_len {
        bail!("PIN shorter than minimum ({min_len})");
    }
    if pin1.len() > max_len {
        bail!("PIN longer than allowed maximum ({max_len})");
    }
    if !pin1.chars().all(|c| c.is_ascii_digit()) {
        bail!("PIN must contain only digits (0-9)");
    }

    fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir))?;
    // Hash (consumes & zeroizes mutable PIN copy)
    let hash = {
        let mut working = pin1.clone();
        hash_pin(&mut working).map_err(|e| anyhow::anyhow!("hashing pin: {e}"))?
    };

    let path = format!("{}/{}.passwd", dir, user);
    // Reset fail counter on new PIN
    let fail_path = format!("{}/{}.fail", dir, user);
    let _ = fs::remove_file(&fail_path);
    let mut f = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .mode(0o600)
        .open(&path)?;
    f.write_all(hash.as_bytes())?;
    f.write_all(b"\n")?;
    drop(f);

    // best-effort ownership/perms
    if Uid::effective().as_raw() == 0 {
        let _ = chown(
            std::path::Path::new(&path),
            Some(Uid::from_raw(0)),
            Some(Gid::from_raw(0)),
        );
        let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o600));
        let _ = fs::set_permissions(&dir, fs::Permissions::from_mode(0o700));
    } else {
        eprintln!("(Not root) Wrote {}. Consider:\n  sudo chown root:root {}\n  sudo chmod 0600 {}\n  sudo chmod 0700 {}\n", path, path, path, dir);
    }

    println!("PIN hash saved to {}", path);
    Ok(())
}
