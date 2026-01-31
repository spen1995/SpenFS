use std::path::PathBuf;
use std::fs;
use std::io::Read;
fn usage_and_exit() -> ! {
    eprintln!("Usage: recipient-add --master <master-file> --wrapped <wrapped-file> --pubkey <recipient-pubkey> --id <id>");
    std::process::exit(2)
}
fn main() {
    let mut args: Vec<String> = std::env::args().collect();
    let mut i = 1;
    let mut master: Option<PathBuf> = None;
    let mut wrapped: Option<PathBuf> = None;
    let mut pubkey: Option<PathBuf> = None;
    let mut id: Option<String> = None;
    let mut operator_seed: Option<PathBuf> = None;
    while i < args.len() {
        match args[i].as_str() {
            "--master" => { i += 1; if i >= args.len() { usage_and_exit(); } master = Some(PathBuf::from(&args[i])); }
            "--wrapped" => { i += 1; if i >= args.len() { usage_and_exit(); } wrapped = Some(PathBuf::from(&args[i])); }
            "--pubkey" => { i += 1; if i >= args.len() { usage_and_exit(); } pubkey = Some(PathBuf::from(&args[i])); }
            "--id" => { i += 1; if i >= args.len() { usage_and_exit(); } id = Some(args[i].clone()); }
            "--operator-seed" => { i += 1; if i >= args.len() { usage_and_exit(); } operator_seed = Some(PathBuf::from(&args[i])); }
            _ => { usage_and_exit(); }
        }
        i += 1;
    }
    let master = master.unwrap_or_else(|| { eprintln!("missing --master"); usage_and_exit(); });
    let wrapped = wrapped.unwrap_or_else(|| { eprintln!("missing --wrapped"); usage_and_exit(); });
    let pubkey = pubkey.unwrap_or_else(|| { eprintln!("missing --pubkey"); usage_and_exit(); });
    let id = id.unwrap_or_else(|| { eprintln!("missing --id"); usage_and_exit(); });

    let mut f = fs::File::open(pubkey).expect("open pubkey");
    let mut buf = Vec::new();
    f.read_to_end(&mut buf).expect("read pubkey");
    // expect raw 32-byte X25519 public key
    if buf.len() != 32 { eprintln!("pubkey must be 32 raw bytes (X25519 public)"); std::process::exit(2); }

    if let Err(e) = spenfs::envelope::add_recipient(&master, &wrapped, &buf, &id) {
        eprintln!("Failed to add recipient: {}", e);
        std::process::exit(1);
    }
    if let Some(seed) = operator_seed {
        if let Err(e) = spenfs::envelope::sign_recipient_list(&wrapped, &seed) {
            eprintln!("Added recipient but failed to sign recipient list: {}", e);
            std::process::exit(1);
        }
        println!("Added and signed recipient {}", id);
    } else {
        println!("Added recipient {} (not signed)", id);
    }
}
