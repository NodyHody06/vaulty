# Changelog

All notable changes to this project are documented in this file.

## v0.1.1 - 2026-02-16

### Added
- Zero-knowledge wrapped-key vault format (v2): a random DEK encrypts vault data and the DEK is wrapped by a passphrase-derived KEK (Argon2id).
- Development-only integrity diagnostics command: `--self-check` (debug builds only).
- Rollback-detection checks tied to vault revision and trusted revision state.

### Changed
- Unlock and save flows now use passphrase-based wrapped-key encryption in the normal path.
- Master passphrase change now re-encrypts through the wrapped-key path.
- Legacy vault formats are migrated to wrapped-key format after successful unlock.
- Documentation updated to reflect wrapped-key zero-knowledge storage.

## v0.1.0 - 2026-02-16

### Added
- Terminal UI for password vault management (services and credentials).
- Terminal UI for notes management with editor integration (`$EDITOR`, fallback `nvim`).
- Clipboard copy with timed auto-clear.
- Idle auto-lock and failed-attempt lockout controls.
- Local encrypted vault storage with restrictive Unix file permissions.
- Configurable vault directory under the user home directory.
