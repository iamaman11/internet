use std::{
    io::Write,
    process::{Command, Stdio},
};

#[test]
fn invalid_choice_does_not_exit_and_zero_exits_without_network_mutation() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_internet"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("CLI executable");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"invalid\n0\n")
        .unwrap();
    let output = child.wait_with_output().expect("menu ended");
    assert!(output.status.success(), "{:?}", output.status);
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert_eq!(stdout.matches("1. Windows").count(), 2);
    assert!(stdout.contains("Unknown choice"));
}

#[test]
fn end_of_input_exits_without_repeating_forever() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_internet"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("CLI executable");
    drop(child.stdin.take());
    let output = child.wait_with_output().expect("menu ended");
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout)
            .unwrap()
            .matches("1. Windows")
            .count(),
        1
    );
}
