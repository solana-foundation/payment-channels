use serde_json::Value;

use std::collections::BTreeSet;
use std::path::Path;

use payment_channels::event_engine::EventDiscriminator;
use payment_channels::events::{Opened, PayoutRedirected};

fn committed_idl() -> Value {
    serde_json::from_str(include_str!("../idl/payment_channels.json")).expect("parse committed IDL")
}

fn instruction<'a>(idl: &'a Value, name: &str) -> &'a Value {
    idl.pointer("/program/instructions")
        .and_then(Value::as_array)
        .expect("instructions")
        .iter()
        .find(|node| node["name"] == name)
        .unwrap_or_else(|| panic!("missing instruction {name}"))
}

fn instruction_account<'a>(instruction: &'a Value, name: &str) -> &'a Value {
    instruction["accounts"]
        .as_array()
        .expect("instruction accounts")
        .iter()
        .find(|node| node["name"] == name)
        .unwrap_or_else(|| panic!("missing account {name}"))
}

#[test]
fn distribute_keeps_dynamic_recipient_token_account_tail() {
    let idl = committed_idl();
    let remaining = instruction(&idl, "distribute")["remainingAccounts"]
        .as_array()
        .expect("distribute remaining accounts");

    assert_eq!(remaining.len(), 1);
    assert_eq!(remaining[0]["kind"], "instructionRemainingAccountsNode");
    assert_eq!(remaining[0]["isWritable"], true);
    assert_eq!(remaining[0]["isSigner"], false);
    assert_eq!(remaining[0]["value"]["kind"], "argumentValueNode");
    assert_eq!(remaining[0]["value"]["name"], "recipientTokenAccounts");
}

#[test]
fn open_self_program_defaults_to_declared_program_id() {
    let idl = committed_idl();
    let open = instruction(&idl, "open");
    let self_program = instruction_account(open, "selfProgram");

    assert_eq!(self_program["defaultValue"]["kind"], "publicKeyValueNode");
    assert_eq!(
        self_program["defaultValue"]["publicKey"],
        idl["program"]["publicKey"]
    );
}

fn events(idl: &Value) -> &Vec<Value> {
    idl.pointer("/program/events")
        .and_then(Value::as_array)
        .expect("events")
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn snake_to_camel(s: &str) -> String {
    let mut out = String::new();
    let mut upper = false;
    for c in s.chars() {
        if c == '_' {
            upper = true;
        } else if upper {
            out.extend(c.to_uppercase());
            upper = false;
        } else {
            out.push(c);
        }
    }
    out
}

/// The committed IDL must declare every emitted event.
#[test]
fn committed_idl_declares_all_emitted_events() {
    let idl = committed_idl();
    let mut names: Vec<&str> = events(&idl)
        .iter()
        .map(|e| e["name"].as_str().expect("event name"))
        .collect();
    names.sort_unstable();
    assert_eq!(names, ["opened", "payoutRedirected"]);
    for event in events(&idl) {
        assert_eq!(event["kind"], "eventNode");
        assert_eq!(
            event["data"]["kind"], "hiddenPrefixTypeNode",
            "event data must follow the nodes-from-anchor convention"
        );
    }
}

/// Pins the hex literals hardcoded in the `#[codama(discriminator(...))]`
/// attributes to the `anchor_event_disc!`-computed program constants.
#[test]
fn idl_event_discriminators_match_program_constants() {
    let idl = committed_idl();
    // New events must be added to this list so their attribute hex stays pinned.
    for (name, disc) in [
        ("opened", <Opened as EventDiscriminator>::DISCRIMINATOR),
        (
            "payoutRedirected",
            <PayoutRedirected as EventDiscriminator>::DISCRIMINATOR,
        ),
    ] {
        let event = events(&idl)
            .iter()
            .find(|e| e["name"] == name)
            .unwrap_or_else(|| panic!("missing event {name}"));
        let discriminators = event["discriminators"].as_array().expect("discriminators");
        assert_eq!(
            discriminators.len(),
            1,
            "{name}: expected one discriminator"
        );
        let node = &discriminators[0];
        assert_eq!(node["kind"], "constantDiscriminatorNode");
        assert_eq!(node["offset"], 0);
        assert_eq!(node["constant"]["value"]["encoding"], "base16");
        assert_eq!(
            node["constant"]["value"]["data"],
            hex(&disc),
            "{name}: discriminator drifted from anchor_event_disc!"
        );
        // The hidden prefix on the event data carries the same constant.
        assert_eq!(event["data"]["prefix"][0]["value"]["data"], hex(&disc));
    }
}

/// Pins the mirror: event types must stay in definedTypes so the renderers
/// keep generating client types for them.
#[test]
fn idl_event_types_remain_in_defined_types() {
    let idl = committed_idl();
    let types: Vec<&str> = idl
        .pointer("/program/definedTypes")
        .and_then(Value::as_array)
        .expect("definedTypes")
        .iter()
        .map(|t| t["name"].as_str().expect("type name"))
        .collect();
    for name in ["opened", "payoutRedirected"] {
        assert!(
            types.contains(&name),
            "definedTypes lost {name}, the normalizeEvents mirror regressed"
        );
    }
}

/// Locks the invariant the enforce-fixed-account-shapes script rests on:
/// handlers with dynamic-tail destructuring (`@ ..`) are exactly the IDL
/// instructions declaring `remainingAccounts`.
#[test]
fn dynamic_tail_handlers_match_idl_remaining_accounts() {
    let idl = committed_idl();
    let idl_tails: BTreeSet<String> = idl
        .pointer("/program/instructions")
        .and_then(Value::as_array)
        .expect("instructions")
        .iter()
        .filter(|ix| {
            ix.get("remainingAccounts")
                .and_then(Value::as_array)
                .is_some_and(|r| !r.is_empty())
        })
        .map(|ix| ix["name"].as_str().expect("instruction name").to_string())
        .collect();

    let src_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/instructions");
    let mut source_tails = BTreeSet::new();
    for entry in std::fs::read_dir(&src_dir).expect("read src/instructions") {
        let path = entry.expect("dir entry").path();
        if path.extension().is_none_or(|e| e != "rs") {
            continue; // skips the helpers/ subdirectory too
        }
        let stem = path.file_stem().unwrap().to_str().unwrap();
        if stem == "mod" {
            continue;
        }
        let source = std::fs::read_to_string(&path).expect("read instruction source");
        if source.contains("@ ..") {
            source_tails.insert(snake_to_camel(stem));
        }
    }

    assert_eq!(
        source_tails, idl_tails,
        "on-chain dynamic-tail handlers and IDL remainingAccounts diverged, \
         update the distribute tail injection in codama-visitors.mjs"
    );
}
