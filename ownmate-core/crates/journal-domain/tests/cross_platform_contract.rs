use serde_json::Value;

#[test]
fn current_cross_platform_fixture_has_stable_canonical_json_and_hash() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../../contracts/journal/v1/fixtures/current-v4.json"
    ))
    .unwrap();
    let input = serde_json::to_string(&fixture["input"]).unwrap();
    let validated = journal_domain::validate_canonicalize_hash_json(&input).unwrap();
    assert_eq!(
        validated.canonical_json,
        fixture["expectedCanonicalJson"].as_str().unwrap(),
    );
    assert_eq!(
        validated.content_hash,
        fixture["expectedSha256"].as_str().unwrap(),
    );
}

#[test]
fn cross_platform_fixture_rejects_platform_asset_identity() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../../contracts/journal/v1/fixtures/current-v4.json"
    ))
    .unwrap();
    let mut input = fixture["input"].clone();
    input["assets"][0]["assetId"] = Value::String(format!("content:{}media/fixture", "//"));
    assert!(journal_domain::validate_canonicalize_hash_json(&input.to_string()).is_err());
}
