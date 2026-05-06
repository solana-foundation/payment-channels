//! Codama IDL build script.

use codama::Codama;
use serde_json::Value;
use std::{env, fs, io, path::Path};

const PROGRAM_NAME: &str = "paymentChannels";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=src/");
    println!("cargo:rerun-if-changed=../payment_channels_core/Cargo.toml");
    println!("cargo:rerun-if-changed=../payment_channels_core/src/");
    println!("cargo:rerun-if-env-changed=GENERATE_IDL");
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_IDL");

    // Only regenerate the IDL when the `idl` feature is active. Cargo
    // sets `CARGO_FEATURE_IDL=1` for this process when the feature is
    // enabled. With it off, codama derives are cfg'd out of the source
    // and Codama::load would see empty derive sites, producing a
    // degraded JSON — skip entirely so plain `cargo build` stays
    // idempotent and the committed IDL isn't clobbered.
    if std::env::var_os("CARGO_FEATURE_IDL").is_none() {
        return Ok(());
    }

    generate_idl()
}

fn generate_idl() -> Result<(), Box<dyn std::error::Error>> {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR")?;
    let crate_path = Path::new(&manifest_dir).join("../payment_channels_core/src");
    let codama = Codama::load(&crate_path)?;
    let idl_json = codama.get_json_idl()?;

    let mut parsed: Value = serde_json::from_str(&idl_json)?;
    let program = parsed
        .get_mut("program")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "IDL missing program node"))?;
    program.insert("name".to_string(), Value::String(PROGRAM_NAME.to_string()));
    program.insert(
        "publicKey".to_string(),
        Value::String(payment_channels_core::ID.to_string()),
    );
    program.insert(
        "version".to_string(),
        Value::String(env!("CARGO_PKG_VERSION").to_string()),
    );

    let mut formatted = serde_json::to_string_pretty(&parsed)?;
    formatted.push('\n');

    let idl_dir = Path::new(&manifest_dir).join("idl");
    fs::create_dir_all(&idl_dir)?;
    let idl_path = idl_dir.join("payment_channels.json");
    fs::write(&idl_path, formatted)?;

    println!("cargo:warning=IDL written to: {}", idl_path.display());
    Ok(())
}
