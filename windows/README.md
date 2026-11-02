# INTERNET S2 Windows candidate

This is part of the existing S2 task in issue #16; no separate deployment plan.

The only supported installation root is `C:\internet`. Windows sing-box runs
under a single on-demand Task Scheduler task, `INTERNET-SingBox`. The Rust
`internet.exe` is short-lived; it does not supervise the dataplane.

The candidate workflow emits `internet-windows-x64.zip` plus
`install.ps1`. The installer verifies every packaged file against
`manifest.json`, preserves `config/` and `state/`, refuses a foreign
installation root, never changes WARP, firewall, DNS or routes, and does not
start the service automatically. The first command is
`C:\internet\internet.exe status --json`. Without restored Vault configuration,
`NOT_CONFIGURED` is correct, **not** a functioning network.

Once a release is published, run the official `install.ps1` with the
same-tag GitHub Release or the offline `-PackagePath`. No Rust, Git or GitHub
CLI is necessary on the target Windows.

## Existing secret store, no new secret service

With WSL Ubuntu and the **full** portable Secret Vault folder (including
`vault/` and `keys/`) restored to its existing path, use the vault's
`doctor`/`status`/`inspect`/`verify` before binding credentials.
The trusted child `windows/configure_from_vault.py` consumes the existing
`internet.vm.dataplane-auth` record through `secret-vault run-file`;
it hands native configuration via stdin directly to `internet.exe configure
--stdin`. Never display the generated native JSON or pipe it through a
user-visible log. It is necessary to verify `miu.alegria.by` TLS and all
12 selector routes physically after configuration.

`internet backup export <external-new-directory>` writes **only two
selectors**, never secrets. To restore: first restore the full protected
Vault folder independently and configure native sing-box, then
`internet restore <selectors-backup-directory>`, then `internet start`.
No backup + no Vault means `NOT_CONFIGURED`, not automatic regeneration.

The desktop and WSL listeners are **loopback only** on ports 2080 and 2081.
WSL-to-Windows loopback must be verified in the actual WSL networking mode;
an inaccessible WSL listener is **not** a successful WSL physical test.
No firewall or NAT modification is permitted as a silent workaround.

## Acceptance boundary

No S2 `PHYSICAL_PASS` until the packaged EXE is installed on the actual
Windows host, native Task Scheduler works after CLI exit, each route's egress
and selectors are verified, repeat install NOOP, failed update rolls back,
Vault-backed scoped restore succeeds, and OpenAI control stays connected.
Actual clean Windows reinstall on a second host remains NOT_TESTED.
