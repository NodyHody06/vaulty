# Terminal Vault (Vaulty)

Terminal-based password and notes vault with a ratatui interface. Unlocks with a master passphrase, encrypts data with a wrapped key, and supports both credential and note management entirely in the terminal.

See `CHANGELOG.md` for versioned release notes.

## Features
- Password vault UI (services -> credentials) with clipboard copy, add, delete (single credential or whole service), change master password.
- Notes vault UI with in-editor editing (uses `$EDITOR`, fallback `nvim`), add/delete, clipboard copy.
- Import a text file into the vault via CLI flag.
- Idle auto-lock (120s) and 3-attempt lockout (2 minutes) on unlock failures.
- Clipboard auto-clear after 20 seconds.
- Data stored in `~/.terminal-vault/{vault.json,lock.json}` with 0o700/0o600 perms on Unix.

## Build & Run
- Build/check: `cargo check`
- Password vault UI: `cargo run -- -p`
- Notes vault UI: `cargo run -- -n`
- Generate strong password (no unlock/keyring, not persisted by the app): `cargo run -- -g`
- Import text file as note: `cargo run -- -t path/to/file.txt`
- Version: `cargo run -- -V`
- Dev-only integrity diagnostics: `cargo run -- --self-check` (debug builds only)
- Running without flags prints usage and exits.
- The project ships two binary names: `vaulty` (primary) and `terminal-vault` (compat).

## Installers and Packages
- GitHub tag release (`vX.Y.Z`) builds artifacts for:
  - Linux (`x86_64-unknown-linux-gnu`)
  - macOS (`x86_64-apple-darwin`, `aarch64-apple-darwin`)
  - Windows (`x86_64-pc-windows-msvc`)
  - Debian package (`.deb`)
- Release workflow: `.github/workflows/release.yml`
- Installer scripts:
  - Unix/macOS: `scripts/install.sh`
  - Windows PowerShell: `scripts/install.ps1`
- Packaging docs and templates: `packaging/README.md`

First run: you'll be prompted for a vault directory (default `~/.terminal-vault`). The app creates it with 0o700 permissions on Unix and saves the choice in `config.json`. Data files inside get 0o600 perms. Everything stays local-there is no cloud sync or external service dependency.

## Key Bindings (Passwords)
- Navigation: left/right focus services/credentials, up/down move selection
- Actions: `Enter`/`c` copy password; `n` add credential; `d` delete (credential when in creds pane; entire service when in services pane); `r` change selected credential password; `m` change master password; `Esc` quit (overlay confirm)

## Key Bindings (Notes)
- Navigation: up/down move; right arrow opens editor; `Enter`/`c` copies note content
- Actions: `n` add note (title prompt overlay -> opens editor); `d` delete; `Esc` quit (overlay confirm)

## Unlock & Lock Behavior
- Master passphrase required at startup.
- 3 failed attempts trigger a 2-minute lock (`lock.json` enforces on next start).
- Idle 120s inside UI exits to protect the vault.

## Storage & Security
- Vault uses wrapped-key encryption: a random 32-byte DEK encrypts vault data (ChaCha20-Poly1305), and that DEK is wrapped by a passphrase-derived KEK (Argon2id).
- Master passphrase is not stored; unlock succeeds only by unwrapping and decrypting.
- Legacy installs may still have `meta.json`/legacy keyring entries, used only for one-time migration.
- Vault saves are atomic (`tempfile` + rename) to reduce corruption risk on crashes.
- Vault revision is tracked and compared with a trusted revision in keyring to detect rollback to older snapshots.
- Files/directories created with restrictive permissions on Unix (0o700 dir, 0o600 files). Non-Unix relies on platform defaults.

## Notes Editing Flow
- Adding: press `n`, enter title in overlay, press `Enter` to launch `$EDITOR`; save/quit editor to store note.
- Importing: `-t <file>` reads file content into a note named after the filename (prompts before overwriting).

## Troubleshooting
- If unlock says vault is locked, wait for the printed remaining seconds then retry.
- If the UI doesn't redraw after editing, ensure your `$EDITOR` exits cleanly; the app re-enters alt screen automatically.
