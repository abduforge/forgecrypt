use std::process::Command;

fn forgecrypt() -> Command {
    Command::new(env!("CARGO_BIN_EXE_forgecrypt"))
}

#[test]
fn version_reports_global_release() {
    let output = forgecrypt()
        .arg("--version")
        .output()
        .expect("binary should run");
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        "ForgeCrypt 2.0.0 GLOBAL"
    );
}

#[test]
fn help_documents_primary_commands() {
    let output = forgecrypt()
        .arg("--help")
        .output()
        .expect("binary should run");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    for command in [
        "forgecrypt encrypt",
        "forgecrypt decrypt",
        "forgecrypt verify",
        "forgecrypt rekey",
        "forgecrypt inspect",
        "forgecrypt doctor",
    ] {
        assert!(
            stdout.contains(command),
            "help output should contain {command}"
        );
    }
}

#[test]
fn unknown_command_exits_with_error() {
    let output = forgecrypt()
        .arg("not-a-command")
        .output()
        .expect("binary should run");
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("invalid command"));
}
