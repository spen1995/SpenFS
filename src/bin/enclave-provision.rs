#[cfg(feature = "enclave-se")]
fn usage_and_exit() -> ! {
    eprintln!("Usage: enclave-provision --label <key-label>\n");
    std::process::exit(2);
}

#[cfg(feature = "enclave-se")]
fn main() -> anyhow::Result<()> {
    let mut args: Vec<String> = std::env::args().collect();
    let mut label: Option<String> = None;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--label" => { i += 1; if i >= args.len() { usage_and_exit(); } label = Some(args[i].clone()); }
            _ => { usage_and_exit(); }
        }
        i += 1;
    }
    let label = label.ok_or_else(|| anyhow::anyhow!("--label is required"))?;
    // Try to create/provision via enclave provider
    match spenfs::enclave_se::EnclaveKeyStore::create_key(&label) {
        Ok(()) => {
            println!("Provisioned Secure Enclave key '{}'", label);
            if let Ok(pk) = spenfs::enclave_se::EnclaveKeyStore::export_pubkey(&label) {
                println!("Public key (hex): {}", hex::encode(pk));
            }
        }
        Err(e) => {
            eprintln!("Failed to provision: {}", e);
            std::process::exit(1);
        }
    }
    Ok(())
}

#[cfg(not(feature = "enclave-se"))]
fn main() -> anyhow::Result<()> {
    eprintln!("enclave-se feature not enabled. Build with --features enclave-se to enable Secure Enclave support.");
    std::process::exit(2);
}
