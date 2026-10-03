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
        "ownmate-mcp 0.2.1\n"
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
