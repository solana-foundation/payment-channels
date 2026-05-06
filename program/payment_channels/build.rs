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
    let idl_json = codama.get_json_idl()?;

    let idl_dir = Path::new(&manifest_dir).join("idl");
    fs::create_dir_all(&idl_dir)?;
    let idl_path = idl_dir.join("payment_channels.raw.json");
    fs::write(&idl_path, idl_json)?;

    println!("cargo:warning=Raw IDL written to: {}", idl_path.display());
    Ok(())
}
