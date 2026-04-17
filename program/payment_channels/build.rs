//! Codama IDL build script.

use codama::Codama;
use std::{env, fs, path::Path};

fn main() {
    println!("cargo:rerun-if-changed=src/");
    println!("cargo:rerun-if-env-changed=GENERATE_IDL");

    if let Err(e) = generate_idl() {
        println!("cargo:warning=Failed to generate IDL: {}", e);
    }
}

fn generate_idl() -> Result<(), Box<dyn std::error::Error>> {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR")?;
    let crate_path = Path::new(&manifest_dir).join("src");
    let codama = Codama::load(&crate_path)?;
    let idl_json = codama.get_json_idl()?;

    let parsed: serde_json::Value = serde_json::from_str(&idl_json)?;
    let mut formatted = serde_json::to_string_pretty(&parsed)?;
    formatted.push('\n');

    let idl_dir = Path::new(&manifest_dir).join("idl");
    fs::create_dir_all(&idl_dir)?;
    let idl_path = idl_dir.join("payment_channels.json");
    fs::write(&idl_path, formatted)?;

    println!("cargo:warning=IDL written to: {}", idl_path.display());
    Ok(())
}
