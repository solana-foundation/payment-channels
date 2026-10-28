//! Codama IDL build script.

#[cfg(feature = "idl")]
use codama::Codama;
#[cfg(feature = "idl")]
use std::{env, fs, path::Path};

type BuildResult<T> = Result<T, Box<dyn std::error::Error>>;

fn main() -> BuildResult<()> {
    println!("cargo:rerun-if-changed=src/");
    println!("cargo:rerun-if-env-changed=GENERATE_IDL");
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_IDL");
    // Solex macros read the channel at expansion time; re-expand when it changes.
    println!("cargo:rerun-if-env-changed=SOLEX_CHANNEL");
    println!("cargo:rerun-if-env-changed=SOLEX_MANIFEST");
    println!("cargo:rerun-if-env-changed=SOLEX_CLUSTER");
    println!("cargo:rerun-if-changed=../../Solex.toml");

    // Only generate the raw IDL when the `idl` feature is active. With it off,
    // codama derives are cfg'd out of the source and Codama::load would see
    // empty derive sites, producing degraded JSON.
    #[cfg(feature = "idl")]
    generate_idl()?;

    Ok(())
}

#[cfg(feature = "idl")]
fn generate_idl() -> BuildResult<()> {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR")?;
    let crate_path = Path::new(&manifest_dir).join("src");
    let codama = Codama::load(&crate_path)?;
    // Codama parses source syntax rather than rustc's cfg-expanded tree, so
    // the raw IDL lists every instruction regardless of channel; the visitors
    // in codama.js split V1/V2. The program id follows the channel being built.
    let mut idl: serde_json::Value = serde_json::from_str(&codama.get_json_idl()?)?;
    let loaded = solex_types::discover(Path::new(&manifest_dir))?;
    let channel = loaded.channels().resolve(None)?;
    let program_id = loaded.channels().program_id(&channel)?;
    idl["program"]["publicKey"] = serde_json::Value::String(program_id.into());
    let idl_json = serde_json::to_string_pretty(&idl)?;

    let idl_dir = Path::new(&manifest_dir).join("idl");
    fs::create_dir_all(&idl_dir)?;
    let idl_path = idl_dir.join(if channel == "canary" {
        "payment_channels_canary.raw.json"
    } else {
        "payment_channels.raw.json"
    });
    fs::write(&idl_path, idl_json)?;

    println!("cargo:warning=Raw IDL written to: {}", idl_path.display());
    Ok(())
}
