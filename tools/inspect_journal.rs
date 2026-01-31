use std::fs::File;
use std::io::Read;
use std::path::PathBuf;

use bincode;
use spenfs::manifest::JournalEntry;

fn print_usage() {
    eprintln!("Usage: inspect_journal <dataset_path>");
}

fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    let ds = if let Some(p) = args.next() { p } else { print_usage(); std::process::exit(2); };
    let mut p = PathBuf::from(ds);
    p.push("journal");
    p.push("journal.log");
    if !p.exists() {
        println!("no journal at {}", p.display());
        return Ok(());
    }
    let mut f = File::open(&p)?;
    loop {
        let mut lenb = [0u8; 4];
        match f.read_exact(&mut lenb) {
            Ok(_) => {}
            Err(e) => { if e.kind() == std::io::ErrorKind::UnexpectedEof { break; } else { return Err(e.into()); } }
        }
        let len = u32::from_le_bytes(lenb) as usize;
        let mut buf = vec![0u8; len];
        f.read_exact(&mut buf)?;
        let entry: JournalEntry = rmp_serde::from_slice(&buf)?;
        println!("JournalEntry seq={} ts={} op={:?}", entry.seq, entry.timestamp, entry.op);
    }
    Ok(())
}
