fn usage_and_exit() -> ! {
    eprintln!("Usage: pkcs11-provision --label <label>");
    eprintln!("Environment: PKCS11_MODULE, PKCS11_SLOT (optional), PKCS11_PIN (or will prompt)");
    std::process::exit(2)
}

fn main() {
    let mut args: Vec<String> = std::env::args().collect();
    let mut i = 1;
    let mut label: Option<String> = None;
    while i < args.len() {
        match args[i].as_str() {
            "--label" => { i += 1; if i >= args.len() { usage_and_exit(); } label = Some(args[i].clone()); }
            _ => { usage_and_exit(); }
        }
        i += 1;
    }
    let label = label.unwrap_or_else(|| { eprintln!("missing --label"); usage_and_exit(); });

    println!("pkcs11 provisioning helper");
    println!("This helper will attempt to find the token via PKCS11_MODULE and PKCS11_SLOT and create a key with label '{}'.", label);
    println!("If your token (YubiKey PIV) supports on-token generation, use vendor tools (ykman) to create an ECC P-256 key with the given label or application-specific id.");
    println!("This CLI is a scaffold; for safety use vendor tooling to provision a YubiKey. After provisioning, set SPENFS_USE_PKCS11=1 and SPENFS_USE_ENCLAVE unset, and run your spenfs commands.");
}
