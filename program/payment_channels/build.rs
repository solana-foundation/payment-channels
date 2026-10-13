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
    // Codama parses source syntax rather than rustc's cfg-expanded tree. Keep
    // default generation on V1 even though the source contains a second ID and
    // a cfg-gated account extension.
    let mut idl: serde_json::Value = serde_json::from_str(&codama.get_json_idl()?)?;
    let v2 = env::var_os("CARGO_FEATURE_V2").is_some();
    idl["program"]["publicKey"] = serde_json::Value::String(
        if v2 {
            "CHNLxBtXw7VPqd5GMcbtVoEbn4ehyaSoiHj56Ao5sWkJ"
        } else {
            "CHNLxYvVA28MJP9PrFuDXccuoGXAx7jBacfLEkahyGsX"
        }
        .into(),
    );
    if !v2 {
        for account in idl["program"]["accounts"]
            .as_array_mut()
            .ok_or("missing accounts")?
        {
            if account["name"] == "channel" {
                account["data"]["fields"]
                    .as_array_mut()
                    .ok_or("missing channel fields")?
                    .retain(|field| field["name"] != "hooks");
            }
        }
    }
    let idl_json = serde_json::to_string_pretty(&idl)?;

    let idl_dir = Path::new(&manifest_dir).join("idl");
    fs::create_dir_all(&idl_dir)?;
    let idl_path = idl_dir.join(if v2 {
        "payment_channels_v2.raw.json"
    } else {
        "payment_channels.raw.json"
    });
    fs::write(&idl_path, idl_json)?;

    println!("cargo:warning=Raw IDL written to: {}", idl_path.display());
    Ok(())
}
