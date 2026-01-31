use std::path::PathBuf;
use std::fs;
use std::io::Write;
fn usage_and_exit() -> ! {
    eprintln!("Usage: unlock --wrapped <wrapped-file> --out <master-out> [--privkey <privkey-file>]");
    std::process::exit(2)
}
fn main() {
    let mut args: Vec<String> = std::env::args().collect();
    let mut i = 1;
    let mut wrapped: Option<PathBuf> = None;
    let mut out: Option<PathBuf> = None;
    let mut privkey: Option<PathBuf> = None;
    let mut operator_pub: Option<PathBuf> = None;
    while i < args.len() {
        match args[i].as_str() {
            "--wrapped" => { i += 1; if i >= args.len() { usage_and_exit(); } wrapped = Some(PathBuf::from(&args[i])); }
            "--out" => { i += 1; if i >= args.len() { usage_and_exit(); } out = Some(PathBuf::from(&args[i])); }
            "--privkey" => { i += 1; if i >= args.len() { usage_and_exit(); } privkey = Some(PathBuf::from(&args[i])); }
            "--operator-pub" => { i += 1; if i >= args.len() { usage_and_exit(); } operator_pub = Some(PathBuf::from(&args[i])); }
            _ => { usage_and_exit(); }
        }
        i += 1;
    }
    let wrapped = wrapped.unwrap_or_else(|| { eprintln!("missing --wrapped"); usage_and_exit(); });
    let out = out.unwrap_or_else(|| { eprintln!("missing --out"); usage_and_exit(); });

    let master = if let Some(pk) = privkey {
        let b = fs::read(pk).expect("read privkey");
        let opk = operator_pub.as_ref().map(|p| fs::read(p).expect("read operator pub"));
        let opk_ref = opk.as_ref().map(|v| v.as_slice());
        match spenfs::envelope::try_unlock_with_x25519_private(&wrapped, &b, opk_ref) {
            Ok(m) => m,
            Err(e) => { eprintln!("local privkey failed: {}", e); std::process::exit(1); }
        }
    } else {
        // Try PKCS#11 token path if feature enabled
        if std::env::var("SPENFS_USE_PKCS11").is_ok() {
            #[cfg(feature = "pkcs11")]
            {
                match crate::pkcs11::try_unlock_with_pkcs11(&wrapped) {
                    Ok(m) => m,
                    Err(e) => { eprintln!("pkcs11 unlock failed: {}", e); std::process::exit(1); }
                }
            }
            #[cfg(not(feature = "pkcs11"))]
            {
                eprintln!("PKCS11 feature not compiled in"); std::process::exit(1);
            }
        } else { eprintln!("no privkey provided and PKCS11 not enabled"); std::process::exit(1); }
    };

    let mut f = fs::OpenOptions::new().create(true).write(true).truncate(true).open(&out).expect("open out");
    f.write_all(&master).expect("write master");
    println!("Wrote master to {}", out.display());
}
