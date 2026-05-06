use serde_json::Value;

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
