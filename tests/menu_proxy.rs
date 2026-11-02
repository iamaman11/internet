use std::process::Command;

#[test]
fn credentials_reveal_rejects_automated_non_tty_without_vault_use() {
    let output = Command::new(env!("CARGO_BIN_EXE_internet"))
        .args(["proxies", "credentials"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(4));
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("PROXY_CREDENTIALS_LOCAL_TERMINAL_ONLY")
    );
}

#[test]
fn credentials_reveal_rejects_json() {
    let output = Command::new(env!("CARGO_BIN_EXE_internet"))
        .args(["proxies", "credentials", "--json"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(4));
    assert!(!String::from_utf8_lossy(&output.stdout).contains("PASSWORD:"));
}
