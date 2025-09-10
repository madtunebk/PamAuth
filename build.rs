// Build script to ensure linking with libcrypt (libxcrypt / glibc) for crypt(3)
fn main() {
    // On GNU/Linux, crypt is in libcrypt; some systems fold into libc but this is safe.
    println!("cargo:rustc-link-lib=crypt");
}
