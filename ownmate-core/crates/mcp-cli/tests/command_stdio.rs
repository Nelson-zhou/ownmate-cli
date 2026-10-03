use std::io::Write;
use std::process::{Command, Stdio};

fn cli() -> Command {
    Command::new(env!("CARGO_BIN_EXE_ownmate-mcp"))
}

#[test]
fn help_and_invalid_doctor_do_not_prompt_or_pollute_stdout() {
    let output = cli().arg("help").stdin(Stdio::null()).output().unwrap();
    assert!(output.status.success());
    assert!(output.stdout.is_empty());
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("doctor --credential-probe")
    );
    let output = cli().arg("doctor").stdin(Stdio::null()).output().unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
}

#[test]
fn update_help_names_the_exact_version_field_from_the_schema() {
    let output = cli()
        .args(["reminders", "update", "--help"])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(output.stdout.is_empty());
    let text = String::from_utf8(output.stderr).unwrap();
    assert!(text.contains("expectedVersion"));
    assert!(!text.contains("originalVersion"));
    let output = cli()
        .args(["reminders", "schema"])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    let schema = String::from_utf8(output.stdout).unwrap();
    assert!(schema.contains("expectedVersion"));
    assert!(!schema.contains("originalVersion"));
}

#[test]
fn version_schema_and_local_validation_emit_json_without_reading_credentials() {
    let output = cli()
        .arg("--version")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        "ownmate-mcp 0.2.2\n"
    );
    let output = cli()
        .args(["reminders", "schema"])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap();
    let mut child = cli()
        .args(["reminders", "validate", "create", "--input", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(br#"{"requestId":"synthetic_request_001","title":"PRIVATE_SYNTHETIC_TITLE","due":{"kind":"none"},"recurrence":"NONE"}"#).unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(!text.contains("PRIVATE_SYNTHETIC_TITLE"));
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&text).unwrap()["submitted"],
        false
    );
}

#[test]
fn every_subcommand_help_is_offline_nonblocking_and_does_not_consume_mcp_stdin() {
    for args in [
        vec!["pair", "--help"],
        vec!["pair", "--setup", "--help"],
        vec!["pair", "status", "--help"],
        vec!["pair", "replace", "--help"],
        vec!["status", "--help"],
        vec!["doctor", "--help"],
        vec!["mcp", "--help"],
        vec!["disconnect", "--help"],
        vec!["list", "--help"],
        vec!["query", "--help"],
        vec!["read", "--help"],
        vec!["reminders", "--help"],
        vec!["reminders", "schema", "--help"],
        vec!["reminders", "validate", "create", "--help"],
        vec!["reminders", "list", "--help"],
        vec!["reminders", "read", "--help"],
        vec!["reminders", "create", "--help"],
        vec!["reminders", "update", "--help"],
        vec!["reminders", "request-status", "--help"],
    ] {
        let mut child = cli()
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(b"PRIVATE_SYNTHETIC_MCP_INPUT\n")
            .unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(output.status.success());
        assert!(output.stdout.is_empty());
        let text = String::from_utf8(output.stderr).unwrap();
        assert!(text.contains("ownmate-mcp"));
        assert!(!text.contains("PRIVATE_SYNTHETIC_MCP_INPUT"));
    }
}

#[test]
fn json_status_never_probes_native_credentials_or_claims_connected_and_control_errors_are_structured()
 {
    let isolated = std::env::temp_dir().join(format!(
        "ownmate-stdio-status-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let output = cli()
        .args(["status", "--json"])
        .env("XDG_STATE_HOME", &isolated)
        .env("LOCALAPPDATA", &isolated)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    assert!(!isolated.exists());
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["connection"]["nativeCredentialChecked"], false);
    assert_eq!(value["connection"]["serverActiveConfirmed"], false);
    assert_eq!(value["connection"]["evidence"], "local_selector_only");
    assert_eq!(value["pairings"], serde_json::json!([]));
    let output = cli()
        .args([
            "pair",
            "replace",
            "--session",
            "PRIVATE_NOT_A_RUN_ID",
            "--json",
        ])
        .env("XDG_STATE_HOME", &isolated)
        .env("LOCALAPPDATA", &isolated)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(!isolated.exists());
    let error: serde_json::Value = serde_json::from_slice(&output.stderr).unwrap();
    assert!(error["reason"].is_string());
    assert!(error["nextAction"].is_string());
    assert!(
        !String::from_utf8(output.stderr)
            .unwrap()
            .contains("PRIVATE_NOT_A_RUN_ID")
    );
}
