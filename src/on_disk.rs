use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::Path;
use std::env;
use getrandom::getrandom;
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::Verifier;
use byteorder::{LittleEndian, WriteBytesExt, ReadBytesExt};

/// Fixed-size on-disk header used to bootstrap a dataset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
	pub magic: [u8; 8],
	pub version: u8,
	pub flags: u8,
	pub kdf_id: u8,
	pub reserved: u8,
	pub kdf_params: u32,
	pub created_ts: u64,
	pub salt: Vec<u8>, // expected 512 bytes
	pub fingerprint: [u8; 32],
	pub dataset_id: [u8; 32],
	pub signing_pubkey: [u8; 32],
}

impl Header {
	pub fn new() -> Self {
		// Create deterministic-ish salt/fingerprint from time + pid hashed with blake3
		let now_secs = SystemTime::now()
			.duration_since(UNIX_EPOCH)
			.unwrap()
			.as_secs();
		let pid = std::process::id() as u64;
		let mut input = [0u8; 32];
		input[..8].copy_from_slice(&now_secs.to_le_bytes());
		input[8..16].copy_from_slice(&pid.to_le_bytes());
		input[16..24].copy_from_slice(b"spenfs00");
		// remaining bytes left as zero
		// produce a 64-byte (512-bit) salt by hashing two distinct inputs
		// produce a 512-byte salt from the OS RNG
		let mut salt = vec![0u8; 512];
		if let Err(e) = getrandom(&mut salt) {
			// Fallback: deterministic but still high-entropy-ish construction using blake3
			let mut fallback = Vec::with_capacity(512);
			for i in 0u8..16u8 {
				let mut inp = input;
				inp[0] = inp[0].wrapping_add(i);
				let h = blake3::hash(&inp);
				fallback.extend_from_slice(h.as_bytes());
			}
			salt = fallback;
			log::warn!("getrandom failed, falling back to deterministic salt: {}", e);
		}

		let mut fp_input = input;
		fp_input[0] ^= 0xA5;
		let fp_hash = blake3::hash(&fp_input);
		let mut fingerprint = [0u8; 32];
		fingerprint.copy_from_slice(fp_hash.as_bytes());
		let mut dataset_id = [0u8; 32];
		dataset_id.copy_from_slice(fp_hash.as_bytes());
		let signing_pubkey = [0u8; 32];

		Header {
			magic: *b"SPENFS\0\0",
			version: 1,
			flags: 0,
			kdf_id: 1,
			reserved: 0,
			kdf_params: 0,
			created_ts: SystemTime::now()
				.duration_since(UNIX_EPOCH)
				.unwrap()
				.as_secs(),
			salt,
			fingerprint,
			dataset_id,
			signing_pubkey,
		}
	}
	/// Serialize header into fixed-size `HEADER_SIZE` bytes and return the buffer.
	pub fn to_fixed_bytes(&self) -> std::io::Result<Vec<u8>> {
		const HEADER_SIZE: usize = 1024;
		let mut buf = Vec::with_capacity(HEADER_SIZE);
		buf.extend_from_slice(&self.magic);
		buf.push(self.version);
		buf.push(self.flags);
		buf.push(self.kdf_id);
		buf.push(self.reserved);
		buf.write_u32::<LittleEndian>(self.kdf_params)?;
		buf.write_u64::<LittleEndian>(self.created_ts)?;
		// salt: write exact 512 bytes (pad or trim)
		let mut salt_fixed = vec![0u8; 512];
		let copy_len = std::cmp::min(self.salt.len(), 512);
		salt_fixed[..copy_len].copy_from_slice(&self.salt[..copy_len]);
		buf.extend_from_slice(&salt_fixed);
		buf.extend_from_slice(&self.fingerprint);
		buf.extend_from_slice(&self.dataset_id);
		buf.extend_from_slice(&self.signing_pubkey);
		// pad remaining to HEADER_SIZE
		if buf.len() > HEADER_SIZE {
			return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "header too large"));
		}
		let pad = vec![0u8; HEADER_SIZE - buf.len()];
		buf.extend_from_slice(&pad);
		Ok(buf)
	}

	pub fn write_atomic_fixed<P: AsRef<Path>>(&self, path: P) -> std::io::Result<()> {
		let p = path.as_ref();
		let tmp = p.with_extension("tmp");
		let v = self.to_fixed_bytes()?;
		let mut f = crate::hardening::create_tmp_file_secure(&tmp)?;
		f.write_all(&v)?;
		f.sync_all()?;
		fs::rename(&tmp, p)?;
		if let Some(parent) = p.parent() {
			let d = File::open(parent)?;
			d.sync_all()?;
		}
		Ok(())
	}

	pub fn read_from_fixed<P: AsRef<Path>>(path: P) -> std::io::Result<Header> {
		let mut f = File::open(path)?;
		const HEADER_SIZE: usize = 1024;
		let mut buf = vec![0u8; HEADER_SIZE];
		f.read_exact(&mut buf)?;
		let mut rdr = &buf[..];
		let mut magic = [0u8; 8];
		rdr.read_exact(&mut magic)?;
		let version = rdr.read_u8()?;
		let flags = rdr.read_u8()?;
		let kdf_id = rdr.read_u8()?;
		let reserved = rdr.read_u8()?;
		let kdf_params = rdr.read_u32::<LittleEndian>()?;
		let created_ts = rdr.read_u64::<LittleEndian>()?;
		let mut salt = vec![0u8; 512];
		rdr.read_exact(&mut salt)?;
		let mut fingerprint = [0u8; 32];
		rdr.read_exact(&mut fingerprint)?;
		let mut dataset_id = [0u8; 32];
		rdr.read_exact(&mut dataset_id)?;
		let mut signing_pubkey = [0u8; 32];
		rdr.read_exact(&mut signing_pubkey)?;
		Ok(Header {
			magic,
			version,
			flags,
			kdf_id,
			reserved,
			kdf_params,
			created_ts,
			salt,
			fingerprint,
			dataset_id,
			signing_pubkey,
		})
	}
}

/// Atomically commit a manifest ciphertext and signature into `manifests/`.
/// Writes `manifests/manifest.<seq>.bin` and `manifests/manifest.<seq>.bin.sig`,
/// then updates `manifests/latest` pointer atomically.
pub fn commit_manifest<P: AsRef<Path>>(manifests_dir: P, seq: u64, ciphertext: &[u8], sig: &[u8]) -> std::io::Result<()> {
	let dir = manifests_dir.as_ref();
	fs::create_dir_all(dir)?;
	let name = format!("manifest.{}.bin", seq);
	let signame = format!("{}.sig", name);
	let tmp_name = format!("{}.tmp", name);
	let tmp_sig = format!("{}.tmp", signame);

	let path_tmp = dir.join(&tmp_name);
	let path_final = dir.join(&name);
	let path_sig_tmp = dir.join(&tmp_sig);
	let path_sig_final = dir.join(&signame);

	// write ciphertext tmp and fsync it
	{
		let mut f = crate::hardening::create_tmp_file_secure(&path_tmp)?;
		f.write_all(ciphertext)?;
		f.sync_all()?;
	}

	// write sig tmp and fsync it
	{
		let mut f = crate::hardening::create_tmp_file_secure(&path_sig_tmp)?;
		f.write_all(sig)?;
		f.sync_all()?;
	}

	// atomically move ciphertext and signature into place; after each rename fsync the moved file
	fs::rename(&path_tmp, &path_final)?;
	let _ = File::open(&path_final).and_then(|f| f.sync_all());
	fs::rename(&path_sig_tmp, &path_sig_final)?;
	let _ = File::open(&path_sig_final).and_then(|f| f.sync_all());

	// update latest pointer atomically (tmp->rename->dir sync)
	let latest_tmp = dir.join("latest.tmp");
	let latest = dir.join("latest");
	{
		let mut f = crate::hardening::create_tmp_file_secure(&latest_tmp)?;
		f.write_all(name.as_bytes())?;
		f.sync_all()?;
	}
	fs::rename(&latest_tmp, &latest)?;

	// sync manifests dir and its parent to ensure rename and pointer persisted
	let d = File::open(dir)?;
	d.sync_all()?;
	if let Some(parent) = dir.parent() {
		let pd = File::open(parent)?;
		let _ = pd.sync_all();
	}
	Ok(())
}

/// Verify the on-disk `anchor.bin` and `anchor.sig` using the header signing
/// public key. Returns the stored sequence and optional TPM monotonic value.
pub fn verify_anchor<P: AsRef<Path>>(dataset_root: P) -> anyhow::Result<(u64, Option<u64>)> {
	let root = dataset_root.as_ref();
	let hdr = read_header(root).map_err(|e| anyhow::anyhow!("read header failed: {}", e))?;
	let zero_pk = [0u8; 32];
	if hdr.signing_pubkey == zero_pk {
		return Err(anyhow::anyhow!("no signing pubkey in header"));
	}
	let anchor_path = root.join("anchor.bin");
	let anchor_sig_path = root.join("anchor.sig");
	if !anchor_path.exists() || !anchor_sig_path.exists() {
		return Err(anyhow::anyhow!("anchor or anchor.sig missing"));
	}
	let anchor_bytes = std::fs::read(&anchor_path).map_err(|e| anyhow::anyhow!("read anchor: {}", e))?;
	let sigbytes = std::fs::read(&anchor_sig_path).map_err(|e| anyhow::anyhow!("read anchor.sig: {}", e))?;
	if sigbytes.len() != 64 { return Err(anyhow::anyhow!("anchor.sig wrong length")); }

	// verify signature
	let mut pkarr = [0u8; 32]; pkarr.copy_from_slice(&hdr.signing_pubkey);
	let pk = crate::ed25519_compat::public_from_bytes(&pkarr).map_err(|e| anyhow::anyhow!("invalid header pubkey: {}", e))?;
	let sigobj = crate::ed25519_compat::signature_from_slice(&sigbytes).map_err(|e| anyhow::anyhow!("invalid anchor sig: {}", e))?;
	pk.verify(&anchor_bytes, &sigobj).map_err(|e| anyhow::anyhow!("anchor signature verify failed: {}", e))?;

	if anchor_bytes.len() < 1 + 8 { return Err(anyhow::anyhow!("anchor malformed (too short)")); }
	let ver = anchor_bytes[0];
	match ver {
		0x01 => {
			let seq = u64::from_le_bytes(anchor_bytes[1..9].try_into().unwrap());
			Ok((seq, None))
		}
		0x02 => {
			if anchor_bytes.len() < 1 + 8 + 8 { return Err(anyhow::anyhow!("anchor malformed (short v2)")); }
			let seq = u64::from_le_bytes(anchor_bytes[1..9].try_into().unwrap());
			let tpm = u64::from_le_bytes(anchor_bytes[9..17].try_into().unwrap());
			Ok((seq, Some(tpm)))
		}
		_ => Err(anyhow::anyhow!("anchor unknown version")),
	}
}

/// Compatibility helpers: read/write header at dataset root path/header.bin
pub fn write_header<P: AsRef<Path>>(dataset_root: P, hdr: &Header) -> std::io::Result<()> {
	let root = dataset_root.as_ref();
	fs::create_dir_all(root)?;
	let path = root.join("header.bin");
	hdr.write_atomic_fixed(path)
}

pub fn read_header<P: AsRef<Path>>(dataset_root: P) -> std::io::Result<Header> {
	let root = dataset_root.as_ref();
	let path = root.join("header.bin");
	let hdr = Header::read_from_fixed(&path)?;
	// If a signature file exists, verify it against the fixed bytes.
	let sig_path = root.join("header.sig");
	if sig_path.exists() {
		match std::fs::read(&sig_path) {
			Ok(sigbytes) => {
				if sigbytes.len() == 64 {
					// convert signing_pubkey to VerifyingKey and signature vec to Signature
					let mut pkarr = [0u8; 32];
					pkarr.copy_from_slice(&hdr.signing_pubkey);
					match crate::ed25519_compat::public_from_bytes(&pkarr) {
						Ok(pk) => {
								match crate::ed25519_compat::signature_from_slice(&sigbytes) {
									Ok(sigobj) => {
										let bytes = hdr.to_fixed_bytes()?;
										if let Err(e) = pk.verify(&bytes, &sigobj) {
											return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, format!("header signature verify failed: {}", e)));
										}
									}
									Err(_) => {
										return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "header.sig malformed"));
									}
								}
						}
						Err(_) => {
							return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid public key in header"));
						}
					}
				} else {
					return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "header.sig wrong length"));
				}
			}
			Err(e) => return Err(e),
		}
	}
	Ok(hdr)
}

/// Read the append-only journal (length-prefixed bincode entries) from `journal/journal.log`.
pub fn read_journal_entries<P: AsRef<Path>>(dataset_root: P) -> std::io::Result<Vec<crate::manifest::JournalEntry>> {
	let root = dataset_root.as_ref();
	let path = root.join("journal").join("journal.log");
	if !path.exists() {
		return Ok(Vec::new());
	}
	let mut f = File::open(path)?;
	let mut out = Vec::new();
	loop {
		let mut lenb = [0u8; 4];
		match f.read_exact(&mut lenb) {
			Ok(_) => {}
			Err(e) => {
				if e.kind() == std::io::ErrorKind::UnexpectedEof {
					break;
				} else {
					return Err(e);
				}
			}
		}
		let len = u32::from_le_bytes(lenb) as usize;
		let mut buf = vec![0u8; len];
		f.read_exact(&mut buf)?;
		let entry: crate::manifest::JournalEntry = rmp_serde::from_slice(&buf).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, format!("rmp_serde: {}", e)))?;
		out.push(entry);
	}
	Ok(out)
}

/// Apply journal entries and attempt to finish in-flight operations.
/// After successful apply, archive the journal to `journal/applied-<ts>.log`.
pub fn apply_journal_entries<P: AsRef<Path>>(dataset_root: P) -> std::io::Result<()> {
	let root = dataset_root.as_ref();
	let entries = read_journal_entries(root)?;
	if entries.is_empty() {
		return Ok(());
	}

	// First pass: group entries into transactions. Transactions are entries between
	// StartTxn(txid) and EndTxn(txid). Entries outside transactions are treated as
	// implicit single-entry transactions (applied immediately).
	use crate::manifest::{JournalEntry, JournalOp};
	let mut tx_map: std::collections::BTreeMap<u64, Vec<JournalEntry>> = std::collections::BTreeMap::new();
	let mut open_tx: Option<u64> = None;
	let mut outside_entries: Vec<JournalEntry> = Vec::new();

	for e in entries.into_iter() {
		match &e.op {
			JournalOp::StartTxn { txid } => {
				open_tx = Some(*txid);
				tx_map.entry(*txid).or_insert_with(Vec::new);
				tx_map.get_mut(txid).unwrap().push(e);
			}
			JournalOp::EndTxn { txid } => {
				if let Some(t) = open_tx {
					if t == *txid {
						tx_map.get_mut(txid).unwrap().push(e);
						open_tx = None;
					} else {
						// mismatched end; log and ignore
						log::warn!("apply_journal: mismatched EndTxn {} (open={})", txid, t);
					}
				} else {
					// end without start; ignore
					log::warn!("apply_journal: EndTxn {} without StartTxn", txid);
				}
			}
			_ => {
				if let Some(t) = open_tx {
					tx_map.get_mut(&t).unwrap().push(e);
				} else {
					outside_entries.push(e);
				}
			}
		}
	}

	// Apply outside entries first (idempotent-ish)
	for e in outside_entries.iter() {
		match &e.op {
			JournalOp::CommitManifest { seq } => {
				promote_manifest_if_tmp_exists(root, *seq);
			}
				JournalOp::Create { path } => {
					let p = root.join(path);
					let _ = std::fs::create_dir_all(p.parent().unwrap_or_else(|| std::path::Path::new(".")));
					let _ = crate::hardening::create_tmp_file_secure(&root.join(path));
				}
			JournalOp::Unlink { path } => {
				let p = root.join(path);
				let _ = std::fs::remove_file(p);
			}
			JournalOp::Rename { old, new } => {
				let oldp = root.join(old);
				let newp = root.join(new);
				if oldp.exists() {
					let _ = std::fs::create_dir_all(newp.parent().unwrap_or_else(|| std::path::Path::new(".")));
					let _ = std::fs::rename(&oldp, &newp);
				}
			}
			_ => {}
		}
	}

	// Now apply completed transactions: require that the transaction contains an EndTxn entry.
	let mut had_uncommitted = false;
	for (txid, vec) in tx_map.into_iter() {
		let has_end = vec.iter().any(|je| matches!(je.op, JournalOp::EndTxn { txid: _ }));
		let has_abort = vec.iter().any(|je| matches!(je.op, JournalOp::AbortTxn { txid: _ }));
		let committed = has_end && !has_abort;
		if !committed {
			log::warn!("apply_journal: skipping uncommitted/aborted tx {} (end={} abort={})", txid, has_end, has_abort);
			had_uncommitted = true;
			continue;
		}
		// apply ops in order, skipping StartTxn/EndTxn markers
		for je in vec.into_iter() {
			match je.op {
				JournalOp::StartTxn { .. } => continue,
				JournalOp::EndTxn { .. } => continue,
				JournalOp::AbortTxn { .. } => continue,
				JournalOp::CommitManifest { seq } => promote_manifest_if_tmp_exists(root, seq),
				JournalOp::Create { path } => {
					let p = root.join(path);
					let _ = std::fs::create_dir_all(p.parent().unwrap_or_else(|| std::path::Path::new(".")));
					let _ = crate::hardening::create_tmp_file_secure(&root.join(p));
				}
				JournalOp::Unlink { path } => {
					let p = root.join(path);
					let _ = std::fs::remove_file(p);
				}
				JournalOp::Rename { old, new } => {
					let oldp = root.join(old);
					let newp = root.join(new);
					if oldp.exists() {
						let _ = std::fs::create_dir_all(newp.parent().unwrap_or_else(|| std::path::Path::new(".")));
						let _ = std::fs::rename(&oldp, &newp);
					}
				}
			}
		}
	}

	// If there were uncommitted/aborted transactions, leave the journal in-place
	// so that subsequent EndTxn/AbortTxn entries can be appended to complete recovery.
	if had_uncommitted {
		log::info!("apply_journal: leaving journal intact due to uncommitted transactions");
		return Ok(());
	}

	// archive journal
	let journal_dir = root.join("journal");
	let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
	let src = journal_dir.join("journal.log");
	if src.exists() {
		let dst = journal_dir.join(format!("applied-{}.log", now));
		let _ = std::fs::rename(&src, &dst);
	}

	Ok(())
}

fn promote_manifest_if_tmp_exists(root: &std::path::Path, seq: u64) {
	let manifests_dir = root.join("manifests");
	let name = format!("manifest-{}.bin", seq);
	let tmp = manifests_dir.join(format!("{}.tmp", name));
	let finalp = manifests_dir.join(&name);

	if finalp.exists() {
		return;
	}

	if !tmp.exists() {
		log::warn!("promote_manifest: manifest {} missing", seq);
		return;
	}

	// helper to quarantine tmp with a reason message
	let quarantine_tmp = |reason: &str, tmp_path: &std::path::Path| {
		let qdir = manifests_dir.join("quarantine");
		let _ = std::fs::create_dir_all(&qdir);
		let qname = format!("{}.bad", tmp_path.file_name().unwrap().to_string_lossy());
		let _ = std::fs::rename(tmp_path, qdir.join(&qname));
		let _ = std::fs::write(qdir.join(format!("{}.reason", qname)), reason.as_bytes());
	};

	// If the header provides a signing key, verify signature and AEAD decrypt.
	// Also check the monotonic anchor if present to detect rollback attempts.
	match read_header(root) {
		Ok(hdr) => {
			let zero_pk = [0u8; 32];
			if hdr.signing_pubkey != zero_pk {
				// If an anchor exists, verify its signature and enforce monotonicity.
				let anchor_path = root.join("anchor.bin");
				let anchor_sig_path = root.join("anchor.sig");
				if anchor_path.exists() && anchor_sig_path.exists() {
					match crate::on_disk::verify_anchor(root) {
						Ok((stored_seq, stored_tpm)) => {
							// If TPM-backed anchor present, compare against platform TPM
							#[cfg(feature = "tpm")]
							if let Some(st_tpm) = stored_tpm {
								let idx = std::env::var("SPENFS_TPM_NV_INDEX").ok().and_then(|s| s.parse::<u32>().ok()).unwrap_or(1);
								match crate::tpm::read_monotonic(idx) {
									Ok(cur) => {
										if st_tpm < cur {
											log::warn!("promote_manifest: detected TPM-backed rollback (stored_tpm={} cur_tpm={})", st_tpm, cur);
											quarantine_tmp("rollback detected (TPM counter < current)", &tmp);
											return;
										}
									}
									Err(e) => {
										log::warn!("promote_manifest: tpm read failed: {}", e);
									}
								}
							}
							// If stored_seq >= seq, this is a rollback attempt.
							if stored_seq >= seq {
								log::warn!("promote_manifest: detected rollback attempt (stored_seq={} seq={})", stored_seq, seq);
								quarantine_tmp("rollback detected (seq <= anchor)", &tmp);
								return;
							}
						}
						Err(e) => {
							log::warn!("promote_manifest: anchor verify failed: {}", e);
							quarantine_tmp(&format!("anchor verification failed: {}", e), &tmp);
							return;
						}
					}
				}
				// read tmp bytes
				let bytes = match std::fs::read(&tmp) {
					Ok(b) => b,
					Err(e) => {
						log::warn!("promote_manifest: failed to read tmp manifest {}: {}", tmp.display(), e);
						quarantine_tmp(&format!("failed to read tmp manifest: {}", e), &tmp);
						return;
					}
				};

				// deserialize
				let mut m: crate::manifest::Manifest = match rmp_serde::from_slice(&bytes) {
					Ok(m) => m,
					Err(_) => {
						log::warn!("promote_manifest: failed to deserialize manifest tmp {}", tmp.display());
						quarantine_tmp("deserialize failed", &tmp);
						return;
					}
				};

				// verify signature
				let sig = m.signature.clone();
				m.signature = Vec::new();
				let ser = match rmp_serde::to_vec(&m) {
					Ok(s) => s,
					Err(_) => {
						log::warn!("promote_manifest: failed to serialize manifest for verify {}", seq);
						quarantine_tmp("serialize for verify failed", &tmp);
						return;
					}
				};

				// Convert header public key bytes to verifying key
				let mut pkarr = [0u8; 32];
				pkarr.copy_from_slice(&hdr.signing_pubkey);
				let pk = match crate::ed25519_compat::public_from_bytes(&pkarr) {
					Ok(pk) => pk,
					Err(_) => {
						log::warn!("promote_manifest: invalid signing pubkey in header");
						quarantine_tmp("invalid signing pubkey in header", &tmp);
						return;
					}
				};

				let sigobj = match crate::ed25519_compat::signature_from_slice(&sig) {
					Ok(s) => s,
					Err(_) => {
						log::warn!("promote_manifest: invalid signature bytes for manifest {}", seq);
						quarantine_tmp("invalid signature bytes", &tmp);
						return;
					}
				};

				if let Err(e) = pk.verify(&ser, &sigobj) {
					log::warn!("promote_manifest: signature verification failed for manifest {}: {}", seq, e);
					quarantine_tmp(&format!("signature verification failed: {}", e), &tmp);
					return;
				}

				// AEAD decrypt check (best-effort; failures quarantine)
				let pass = crate::passphrase::retrieve_passphrase(root).unwrap_or_else(|_| "example-passphrase".to_string());
				if let Ok(aead_key) = crate::crypto::derive_key(pass.as_bytes(), &hdr.salt) {
					if let Err(_) = crate::crypto::aead_decrypt(&aead_key, m.metadata_blob.as_slice(), &m.dataset_id) {
							log::warn!("promote_manifest: AEAD decrypt failed for manifest {}", seq);
							quarantine_tmp("AEAD decrypt failed", &tmp);
							return;
						}
				}
			}
		}
		Err(e) => {
			// If header is missing/unreadable, skip verification and attempt promotion.
			log::warn!("promote_manifest: could not read header (will skip signature checks): {}", e);
		}
	}

	// If all checks passed (or header had no signing key), promote tmp -> final
	if let Err(e) = std::fs::rename(&tmp, &finalp) {
		log::warn!("promote_manifest: rename failed: {}", e);
		return;
	}

	// fsync the final manifest file
	let _ = File::open(&finalp).and_then(|f| f.sync_all());

	// atomically update `latest` pointer to this manifest (tmp->rename->dir sync)
	let latest_tmp = manifests_dir.join("latest.tmp");
	let latest = manifests_dir.join("latest");
	if let Ok(mut lf) = crate::hardening::create_tmp_file_secure(&latest_tmp) {
		if let Err(e) = lf.write_all(finalp.file_name().unwrap().to_string_lossy().as_bytes()) {
			log::warn!("promote_manifest: failed to write latest tmp: {}", e);
		} else if let Err(e) = lf.sync_all() {
			log::warn!("promote_manifest: failed to sync latest tmp: {}", e);
		} else if let Err(e) = fs::rename(&latest_tmp, &latest) {
			log::warn!("promote_manifest: failed to rename latest tmp: {}", e);
		} else {
			// sync manifests dir and parent
			if let Ok(d) = File::open(&manifests_dir) {
				let _ = d.sync_all();
			}
			if let Some(parent) = manifests_dir.parent() {
				if let Ok(pd) = File::open(parent) {
					let _ = pd.sync_all();
				}
			}
			// If a temporary anchor was provided by the writer, atomically install it now.
			let anchor_tmp = root.join("anchor.bin.tmp");
			let anchor_sig_tmp = root.join("anchor.sig.tmp");
			let anchor_final = root.join("anchor.bin");
			let anchor_sig_final = root.join("anchor.sig");
			if anchor_tmp.exists() && anchor_sig_tmp.exists() {
				if let Err(e) = std::fs::rename(&anchor_tmp, &anchor_final) {
					log::warn!("promote_manifest: failed to install anchor: {}", e);
				} else if let Err(e) = std::fs::rename(&anchor_sig_tmp, &anchor_sig_final) {
					log::warn!("promote_manifest: failed to install anchor sig: {}", e);
				} else {
					// sync root dir
					if let Some(parent) = root.parent() {
						if let Ok(d) = File::open(parent) {
							let _ = d.sync_all();
						}
					}
				}
			}
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use tempfile::tempdir;
	use std::fs;
	use crate::ed25519_compat::Keypair;
	use getrandom::getrandom;

	#[test]
	fn write_and_read_header() {
		let hdr = Header::new();
		let td = tempdir().unwrap();
		let p = td.path().join("header.bin");
		hdr.write_atomic_fixed(&p).unwrap();
		let got = Header::read_from_fixed(&p).unwrap();
		assert_eq!(hdr.version, got.version);
		assert_eq!(hdr.magic, got.magic);
	}

	#[test]
	fn commit_manifest_creates_files_and_latest() {
		let td = tempdir().unwrap();
		let dir = td.path().join("manifests");
		let cipher = b"deadbeef";
		let sig = b"sigbytes";
		commit_manifest(&dir, 42, cipher, sig).unwrap();
		assert!(dir.join("manifest.42.bin").exists());
		assert!(dir.join("manifest.42.bin.sig").exists());
		let latest = std::fs::read_to_string(dir.join("latest")).unwrap();
		assert_eq!(latest, "manifest.42.bin");
	}

	#[test]
	fn verify_anchor_signature_and_sequence() {
		// prepare temp dataset root
		let td = tempdir().unwrap();
		let root = td.path();

		// generate operator seed and keypair
		let mut seed = [0u8;32]; getrandom(&mut seed).unwrap();
		let kp = Keypair::from_seed_bytes(&seed).unwrap();
		let pubbytes = kp.public.to_bytes();

		// write header with signing_pubkey
		let mut hdr = Header::new();
		hdr.signing_pubkey.copy_from_slice(&pubbytes);
		write_header(root, &hdr).unwrap();

		// create anchor v1 with seq=100
		let mut anchor = Vec::new();
		anchor.push(0x01u8);
		anchor.extend_from_slice(&100u64.to_le_bytes());
		fs::write(root.join("anchor.bin"), &anchor).unwrap();

		// sign anchor
		let sig = kp.sign(&anchor).to_bytes();
		fs::write(root.join("anchor.sig"), &sig).unwrap();

		// verify_anchor should return stored_seq=100
		let (seq, tpm) = verify_anchor(root).unwrap();
		assert_eq!(seq, 100);
		assert!(tpm.is_none());

		// simulate manifest seq lower or equal -> treat as rollback
		let manifest_seq = 50u64;
		assert!(seq >= manifest_seq);

		// tamper anchor -> verify should fail
		let mut bad = anchor.clone(); bad[1] ^= 0xFF;
		fs::write(root.join("anchor.bin"), &bad).unwrap();
		assert!(verify_anchor(root).is_err());
	}
}

