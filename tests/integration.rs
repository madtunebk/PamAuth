#![cfg(any(feature = "sha-crypt", feature = "argon2"))]
use std::fs;
use std::io::Write;
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

#[cfg(feature = "argon2")]
const TEST_SCHEME: &str = "argon2";
#[cfg(all(not(feature = "argon2"), feature = "sha-crypt"))]
const TEST_SCHEME: &str = "sha-crypt"; // env value ignored for plain $6$ but harmless
#[cfg(all(not(feature = "argon2"), not(feature = "sha-crypt")))]
const TEST_SCHEME: &str = ""; // no scheme

#[test]
fn end_to_end_pin_dir() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    // generate pin
    let status = Command::new(env!("CARGO_BIN_EXE_genpin"))
        .env("PIN_DIR", dir)
        .env("GENPIN_NONINTERACTIVE", "2468")
        .env("PIN_MAX_LEN", "6")
        .env("PIN_SCHEME", TEST_SCHEME)
        .arg("alice")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(status.success(), "genpin failed");
    let stored = dir.join("alice.passwd");
    assert!(stored.exists(), "hash file missing");

    // verify correct PIN
    let status = Command::new(env!("CARGO_BIN_EXE_check_pin"))
        .env("PAM_USER", "alice")
        .env("PIN_DIR", dir)
        .env("PIN_SCHEME", TEST_SCHEME)
        .env("PIN_MAX_LEN", "6")
        .stdin(Stdio::piped())
        .spawn()
        .map(|mut c| {
            c.stdin.as_mut().unwrap().write_all(b"2468\n").unwrap();
            c.wait().unwrap()
        })
        .unwrap();
    assert!(status.success(), "correct PIN rejected");

    // induce failures up to threshold 3
    for i in 0..3 {
        let bad = Command::new(env!("CARGO_BIN_EXE_check_pin"))
            .env("PAM_USER", "alice")
            .env("PIN_DIR", dir)
            .env("PIN_SCHEME", TEST_SCHEME)
            .env("PIN_MAX_FAILS", "3")
            .env("PIN_MAX_LEN", "6")
            .stdin(Stdio::piped())
            .spawn()
            .map(|mut c| {
                c.stdin.as_mut().unwrap().write_all(b"0000\n").unwrap();
                c.wait().unwrap()
            })
            .unwrap();
        assert!(!bad.success(), "wrong PIN accepted on attempt {i}");
    }
    // Now even correct PIN should fail (lockout) until reset
    let locked = Command::new(env!("CARGO_BIN_EXE_check_pin"))
        .env("PAM_USER", "alice")
        .env("PIN_DIR", dir)
        .env("PIN_SCHEME", TEST_SCHEME)
        .env("PIN_MAX_FAILS", "3")
        .env("PIN_MAX_LEN", "6")
        .stdin(Stdio::piped())
        .spawn()
        .map(|mut c| {
            c.stdin.as_mut().unwrap().write_all(b"2468\n").unwrap();
            c.wait().unwrap()
        })
        .unwrap();
    assert!(!locked.success(), "lockout did not trigger");

    let bad = Command::new(env!("CARGO_BIN_EXE_check_pin"))
        .env("PAM_USER", "alice")
        .env("PIN_DIR", dir)
        .env("PIN_SCHEME", TEST_SCHEME)
        .env("PIN_MAX_LEN", "6")
        .stdin(Stdio::piped())
        .spawn()
        .map(|mut c| {
            c.stdin.as_mut().unwrap().write_all(b"0000\n").unwrap();
            c.wait().unwrap()
        })
        .unwrap();
    assert!(!bad.success(), "wrong PIN accepted");
}

#[test]
fn no_username_noop() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    let status = Command::new(env!("CARGO_BIN_EXE_genpin"))
        .env("PIN_DIR", dir)
        .env("GENPIN_NONINTERACTIVE", "1357")
        .status()
        .unwrap();
    assert!(status.success(), "genpin without username should succeed (noop)");
    assert_eq!(fs::read_dir(dir).unwrap().count(), 0, "No files should be created when username missing");
}

#[test]
fn timed_lockout_expires() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    // create PIN
    let status = Command::new(env!("CARGO_BIN_EXE_genpin"))
        .env("PIN_DIR", dir)
        .env("GENPIN_NONINTERACTIVE", "1111")
        .arg("bob")
        .status()
        .unwrap();
    assert!(status.success());

    // Trigger failures threshold=2 lockout=2s
    for _ in 0..2 {
        let bad = Command::new(env!("CARGO_BIN_EXE_check_pin"))
            .env("PAM_USER", "bob")
            .env("PIN_DIR", dir)
            .env("PIN_MAX_FAILS", "2")
            .env("PIN_LOCKOUT_SECS", "2")
            .stdin(Stdio::piped())
            .spawn()
            .map(|mut c| {
                c.stdin.as_mut().unwrap().write_all(b"0000\n").unwrap();
                c.wait().unwrap()
            })
            .unwrap();
        assert!(!bad.success());
    }
    // Should still be locked even with correct PIN
    let locked = Command::new(env!("CARGO_BIN_EXE_check_pin"))
        .env("PAM_USER", "bob")
        .env("PIN_DIR", dir)
        .env("PIN_MAX_FAILS", "2")
        .env("PIN_LOCKOUT_SECS", "2")
        .stdin(Stdio::piped())
        .spawn()
        .map(|mut c| {
            c.stdin.as_mut().unwrap().write_all(b"1111\n").unwrap();
            c.wait().unwrap()
        })
        .unwrap();
    assert!(!locked.success(), "lockout not in effect");

    thread::sleep(Duration::from_secs(3)); // allow lockout to expire

    // Now correct PIN should succeed again
    let ok = Command::new(env!("CARGO_BIN_EXE_check_pin"))
        .env("PAM_USER", "bob")
        .env("PIN_DIR", dir)
        .env("PIN_MAX_FAILS", "2")
        .env("PIN_LOCKOUT_SECS", "2")
        .stdin(Stdio::piped())
        .spawn()
        .map(|mut c| {
            c.stdin.as_mut().unwrap().write_all(b"1111\n").unwrap();
            c.wait().unwrap()
        })
        .unwrap();
    assert!(ok.success(), "lockout did not expire");
}
