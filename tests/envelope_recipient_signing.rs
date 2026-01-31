use anyhow::Context;
use tempfile::tempdir;
use std::fs;
use std::path::PathBuf;

#[test]
fn recipient_list_sign_and_tamper() -> anyhow::Result<()> {
    let td = tempdir()?;
    let master = td.path().join("master.bin");
    let wrapped = td.path().join("wrapped.json");
    // write 32-byte master
    let mut m = [0u8;32];
    getrandom::getrandom(&mut m).context("getrandom")?;
    fs::write(&master, &m)?;

    // generate recipient x25519 keypair
    let mut sk_bytes = [0u8;32];
    getrandom::getrandom(&mut sk_bytes)?;
    let sk = x25519_dalek::StaticSecret::from(sk_bytes);
    let pk = x25519_dalek::PublicKey::from(&sk);
    let pk_bytes = pk.as_bytes();

    // add recipient
    spenfs::envelope::add_recipient(&master, &wrapped, pk_bytes, "r1")?;

    // create operator seed and write
    let mut seed = [0u8;32];
    getrandom::getrandom(&mut seed)?;
    let seed_path = td.path().join("operator.seed");
    fs::write(&seed_path, &seed)?;

    // sign recipient list
    spenfs::envelope::sign_recipient_list(&wrapped, &seed_path)?;

    // derive operator pubkey bytes
    let op_kp = spenfs::ed25519_compat::Keypair::from_seed_bytes(&seed)?;
    let op_pub = op_kp.public.to_bytes();

    // verify recipient list
    spenfs::envelope::verify_recipient_list(&wrapped, &op_pub)?;

    // try unlock with private key and operator pub (should succeed)
    let master_out = spenfs::envelope::try_unlock_with_x25519_private(&wrapped, &sk_bytes, Some(&op_pub))?;
    assert_eq!(master_out, m.to_vec());

    // tamper recipients
    let mut s = fs::read_to_string(&wrapped)?;
    let mut j: serde_json::Value = serde_json::from_str(&s)?;
    if let Some(r) = j.get_mut("recipients") {
        if let Some(arr) = r.as_array_mut() {
            if !arr.is_empty() {
                if let Some(obj) = arr[0].as_object_mut() {
                    obj.insert("id".to_string(), serde_json::Value::String("bad".to_string()));
                }
            }
        }
    }
    let s2 = serde_json::to_string_pretty(&j)?;
    fs::write(&wrapped, &s2)?;

    // verify should fail
    assert!(spenfs::envelope::verify_recipient_list(&wrapped, &op_pub).is_err());
    assert!(spenfs::envelope::try_unlock_with_x25519_private(&wrapped, &sk_bytes, Some(&op_pub)).is_err());
    Ok(())
}
