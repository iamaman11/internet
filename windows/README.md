# INTERNET S2 Windows candidate

This is part of the existing S2 task in issue #16; no separate deployment plan.

The only supported installation root is `C:\internet`. Windows sing-box runs
under a single on-demand Task Scheduler task, `INTERNET-SingBox`. The Rust
`internet.exe` is short-lived; it does not supervise the dataplane. Windows bootstrap
registers the native task exactly once with SYSTEM identity and no triggers. The
normal `internet start` only starts that pre-existing verified task: it never
creates persistence, services or scheduler entries.

The candidate workflow emits `internet-windows-x64.zip` plus
`install.ps1`. The installer verifies every packaged file against
`manifest.json`, preserves `config/` and `state/`, refuses a foreign
installation root, never changes WARP, firewall, DNS or routes, and registers the on-demand task without starting it automatically. The first command is
`C:\internet\internet.exe status --json`. Without restored Vault configuration,
`NOT_CONFIGURED` is correct, **not** a functioning network.

Once a release is published, run the official `install.ps1` with the
same-tag GitHub Release or the offline `-PackagePath`. No Rust, Git or GitHub
CLI is necessary on the target Windows.

## Existing secret store, no new secret service

With WSL Ubuntu and the **full** portable Secret Vault folder (including
`vault/` and `keys/`) restored to its existing path, use the vault's
`doctor`/`status`/`inspect`/`verify` before binding credentials.
Before the Vault-backed configuration step, obtain the **current IPv4** by
authenticated Vultr readback of the exact INTERNET VM UUID and supply it as
INTERNET_VM_IPV4 to the trusted child. A missing/private/invalid IPv4 fails
closed; no previous VM address is embedded in the renderer or Rust validator.
The four native outbound endpoints must match one public IPv4. This input is
configuration (not a secret), not a new discovery service or state store.

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

Desktop is loopback-only on 2080. The WSL listener is authenticated on port 2081.\nAt explicit \`internet start\`, the native adapter discovers the current WSL NAT\ngateway, binds only that Windows interface, and installs/updates exactly one\napplication-owned inbound firewall rule restricted to the observed WSL IPv4.\nNo other ports, host routes, WARP or control resources are changed. An absent\nWSL instance keeps 2081 on loopback without opening a firewall rule. The\nactual WSL-to-Windows connection is checked separately; a TCP connection alone\ndoes not prove the remote egress.
No firewall or NAT modification is permitted as a silent workaround.

## Acceptance boundary

No S2 `PHYSICAL_PASS` until the packaged EXE is installed on the actual
Windows host, native Task Scheduler works after CLI exit, each route's egress
and selectors are verified, repeat install NOOP, failed update rolls back,
Vault-backed scoped restore succeeds, and OpenAI control stays connected.
Actual clean Windows reinstall on a second host remains NOT_TESTED.