use std::env;
use std::process::Command;
use anyhow::Context;

fn usage_and_exit() -> ! {
    eprintln!("Usage: tpm-provision --index <hex or dec> [--size <bytes>] [--initial <u64>] [--auth-file <path>]\n");
    std::process::exit(2);
}

fn main() -> anyhow::Result<()> {
    let mut args: Vec<String> = env::args().collect();
    let mut index: Option<u32> = None;
    let mut size: u16 = 16;
    let mut initial: Option<u64> = None;
    let mut auth_file: Option<String> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--index" => {
                i += 1; if i >= args.len() { usage_and_exit(); }
                let s = &args[i];
                let idx = if s.starts_with("0x") || s.starts_with("0X") { u32::from_str_radix(&s[2..], 16)? } else { s.parse()? };
                index = Some(idx);
            }
            "--size" => { i += 1; if i >= args.len() { usage_and_exit(); } size = args[i].parse()?; }
            "--initial" => { i += 1; if i >= args.len() { usage_and_exit(); } initial = Some(args[i].parse()?); }
            "--auth-file" => { i += 1; if i >= args.len() { usage_and_exit(); } auth_file = Some(args[i].clone()); }
            _ => { usage_and_exit(); }
        }
        i += 1;
    }

    let index = index.context("--index is required")?;
    println!("Provisioning NV index 0x{:X} size {}...", index, size);

    // Invoke system `tpm2_nvdefine` (operator should have tpm2-tools installed)
    let idx_str = format!("0x{:X}", index);
    let status = Command::new("tpm2_nvdefine")
        .args(&["-s", &size.to_string(), &idx_str])
        .status()
        .context("failed to execute tpm2_nvdefine")?;
    if !status.success() {
        anyhow::bail!("tpm2_nvdefine failed");
    }
    println!("nv index defined via tpm2_nvdefine");

    if let Some(init) = initial {
        // write initial value as little-endian u64
        let mut b = init.to_le_bytes().to_vec();
        // write via tpm2_nvwrite
        let idx_str = format!("0x{:X}", index);
        let mut cmd = Command::new("tpm2_nvwrite");
        cmd.args(&[&idx_str, "-i", "-"]);
        let mut child = cmd.stdin(std::process::Stdio::piped()).spawn().context("spawn tpm2_nvwrite")?;
        use std::io::Write;
        child.stdin.as_mut().unwrap().write_all(&b).context("write to tpm2_nvwrite stdin")?;
        let st = child.wait().context("wait tpm2_nvwrite")?;
        if !st.success() { anyhow::bail!("tpm2_nvwrite failed"); }
        println!("wrote initial value {}", init);
    }

    Ok(())
}
