use std::process::Command;

fn forgecrypt() -> Command {
    Command::new(env!("CARGO_BIN_EXE_forgecrypt"))
}

#[test]
fn version_reports_package_version() {
    let output = forgecrypt()
        .arg("--version")
        .output()
        .expect("forgecrypt binary should run");
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        "ForgeCrypt 1.2.0"
    );
}

#[test]
fn help_documents_verify_and_rekey() {
    let output = forgecrypt()
        .arg("--help")
        .output()
        .expect("forgecrypt binary should run");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("forgecrypt verify <file>"));
    assert!(stdout.contains("forgecrypt rekey <input> <output>"));
}
