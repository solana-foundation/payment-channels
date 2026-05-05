//! Codama IDL build script.

use codama::Codama;
use serde_json::{Value, json};
use std::{env, fs, path::Path};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=src/");
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
    let crate_path = Path::new(&manifest_dir).join("src");
    let codama = Codama::load(&crate_path)?;
    let idl_json = codama.get_json_idl()?;

    let mut parsed: Value = serde_json::from_str(&idl_json)?;
    inject_dynamic_distribution_args(&mut parsed)?;

    let mut formatted = serde_json::to_string_pretty(&parsed)?;
    formatted.push('\n');

    let idl_dir = Path::new(&manifest_dir).join("idl");
    fs::create_dir_all(&idl_dir)?;
    let idl_path = idl_dir.join("payment_channels.json");
    fs::write(&idl_path, formatted)?;

    println!("cargo:warning=IDL written to: {}", idl_path.display());
    Ok(())
}

/// Codama cannot derive the dynamic `open` / `distribute` argument structs
/// directly from the on-chain Rust types: those types borrow instruction-data
/// bytes instead of owning client-serializable fields. Patch the generated IDL
/// with the canonical wire shape so the committed IDL is standalone and the
/// client-generation visitor can stay idempotent.
fn inject_dynamic_distribution_args(idl: &mut Value) -> Result<(), Box<dyn std::error::Error>> {
    let program = idl
        .get_mut("program")
        .and_then(Value::as_object_mut)
        .ok_or("IDL missing program object")?;

    let defined_types = program
        .get_mut("definedTypes")
        .and_then(Value::as_array_mut)
        .ok_or("IDL missing program.definedTypes array")?;

    upsert_defined_type(defined_types, distribution_recipients_type());
    upsert_defined_type(defined_types, open_args_type());
    upsert_defined_type(defined_types, distribute_args_type());

    let instructions = program
        .get_mut("instructions")
        .and_then(Value::as_array_mut)
        .ok_or("IDL missing program.instructions array")?;

    for instruction in instructions {
        match instruction.get("name").and_then(Value::as_str) {
            Some("open") => rename_arg0(instruction, "openArgs", "openArgs")?,
            Some("distribute") => rename_arg0(instruction, "distributeArgs", "distributeArgs")?,
            _ => {}
        }
    }

    Ok(())
}

fn upsert_defined_type(defined_types: &mut Vec<Value>, node: Value) {
    let name = node
        .get("name")
        .and_then(Value::as_str)
        .expect("defined type node has a name");

    if let Some(existing) = defined_types
        .iter_mut()
        .find(|type_node| type_node.get("name").and_then(Value::as_str) == Some(name))
    {
        *existing = node;
    } else {
        defined_types.push(node);
    }
}

fn rename_arg0(
    instruction: &mut Value,
    argument_name: &str,
    type_name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let arguments = instruction
        .get_mut("arguments")
        .and_then(Value::as_array_mut)
        .ok_or("IDL instruction missing arguments array")?;

    for argument in arguments {
        let name = argument.get("name").and_then(Value::as_str);
        let linked_type = argument
            .get("type")
            .and_then(|type_node| type_node.get("name"))
            .and_then(Value::as_str);

        if matches!(name, Some("arg0")) || linked_type == Some(type_name) {
            argument["name"] = Value::String(argument_name.to_owned());
            argument["type"] = defined_type_link(type_name);
        }
    }

    Ok(())
}

fn distribution_recipients_type() -> Value {
    json!({
        "kind": "definedTypeNode",
        "name": "distributionRecipients",
        "type": {
            "kind": "arrayTypeNode",
            "item": defined_type_link("distributionEntry"),
            "count": {
                "kind": "prefixedCountNode",
                "prefix": number_type("u8"),
            },
        },
    })
}

fn open_args_type() -> Value {
    json!({
        "kind": "definedTypeNode",
        "name": "openArgs",
        "type": {
            "kind": "structTypeNode",
            "fields": [
                struct_field("salt", number_type("u64")),
                struct_field("deposit", number_type("u64")),
                struct_field("gracePeriod", number_type("u32")),
                struct_field("recipients", defined_type_link("distributionRecipients")),
            ],
        },
    })
}

fn distribute_args_type() -> Value {
    json!({
        "kind": "definedTypeNode",
        "name": "distributeArgs",
        "type": {
            "kind": "structTypeNode",
            "fields": [
                struct_field("recipients", defined_type_link("distributionRecipients")),
            ],
        },
    })
}

fn struct_field(name: &str, field_type: Value) -> Value {
    json!({
        "kind": "structFieldTypeNode",
        "name": name,
        "type": field_type,
    })
}

fn number_type(format: &str) -> Value {
    json!({
        "kind": "numberTypeNode",
        "format": format,
        "endian": "le",
    })
}

fn defined_type_link(name: &str) -> Value {
    json!({
        "kind": "definedTypeLinkNode",
        "name": name,
    })
}
