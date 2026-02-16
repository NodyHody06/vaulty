use std::fs;
use std::io::{self, Write};
use std::path::{Component, Path};
use std::process::Command;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Result};
use argon2::password_hash::{PasswordHash, PasswordVerifier};
use argon2::Argon2;
use crossterm::{
    cursor::{Hide, Show},
    event::{self, Event, KeyCode, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use rand::rngs::OsRng;
use rand::seq::SliceRandom;
use ratatui::{backend::CrosstermBackend, Terminal};
use tempfile::NamedTempFile;
use zeroize::Zeroize;

use crate::models::{Entry, Note, Vault};
use crate::storage::{
    default_base_dir, ensure_lock_not_active, ensure_parent_dir, is_wrapped_vault_file, load_config,
    load_meta, load_trusted_revision, load_vault, load_vault_legacy, load_vault_with_key,
    load_wrapped_key, lock_path, meta_path, save_config, save_vault, set_lock, store_trusted_revision,
    vault_path,
};
use crate::ui::{
    classify_password_strength, copy_password_to_clipboard, draw, draw_notes, draw_unlock,
    prompt_new_master_password, validate_master_passphrase, NoteViewState, StatusStrength,
    UnlockState, ViewState,
};

const MAX_ATTEMPTS: u8 = 3;
const LOCK_SECONDS: u64 = 120;
const IDLE_TIMEOUT_SECS: u64 = 120;
const STATUS_MESSAGE_SECS: u64 = 2;
const PASSWORD_NAV_HINT: &str =
    "←/→ focus | ↑/↓ move | Enter/c copy | n add | d delete | r change password | m change master | Esc quit";
const NOTES_NAV_HINT: &str = "Notes mode: ↑/↓ move | → edit | n add | d delete | Esc quit";

pub fn run() -> Result<()> {
    let bin_name = executable_name();
    let mut args = std::env::args().skip(1);
    let mut text_path: Option<std::path::PathBuf> = None;
    let mut mode_password = false;
    let mut mode_notes = false;
    let mut mode_generate = false;
    let mut self_check = false;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--version" | "-V" => {
                println!("{bin_name} v{}", env!("CARGO_PKG_VERSION"));
                return Ok(());
            }
            "-t" | "--text" => {
                if let Some(p) = args.next() {
                    text_path = Some(std::path::PathBuf::from(p));
                } else {
                    return Err(anyhow!("--text requires a path"));
                }
            }
            "-p" | "--passwords" => mode_password = true,
            "-n" | "--notes" => mode_notes = true,
            "-g" | "--generate" => mode_generate = true,
            "--self-check" => self_check = true,
            _ => {}
        }
    }

    if self_check {
        #[cfg(debug_assertions)]
        {
            return run_self_check();
        }
        #[cfg(not(debug_assertions))]
        {
            return Err(anyhow!("--self-check is only available in development builds"));
        }
    }

    if mode_generate {
        let mut generated = generate_strong_password(20);
        println!("{generated}");
        generated.zeroize();
        return Ok(());
    }

    if !mode_password && !mode_notes && text_path.is_none() {
        print_usage(&bin_name);
        return Ok(());
    }

    let _ = select_or_init_base_dir()?;
    let path = vault_path()?;
    let lock_file = lock_path()?;
    let meta_file = meta_path()?;
    ensure_parent_dir(&path)?;
    ensure_parent_dir(&lock_file)?;
    ensure_lock_not_active(&lock_file)?;

    let fresh = !path.exists();

    let (mut vault, mut master_password) = if fresh {
        initialize_new_vault(&path)?
    } else {
        unlock_screen(&path, &meta_file, &lock_file)?
    };

    if let Some(text_path) = text_path {
        handle_text_mode(text_path, &mut vault, &master_password, &path)?;
        return Ok(());
    }

    if mode_notes && !mode_password {
        run_tui_notes(&mut vault, &mut master_password, &path)?;
    } else {
        run_tui_passwords(&mut vault, &mut master_password, &path)?;
    }

    zeroize_sensitive(&mut vault, &mut master_password);
    Ok(())
}

fn zeroize_sensitive(vault: &mut Vault, master_password: &mut String) {
    for entry in &mut vault.entries {
        entry.name.zeroize();
        entry.email.zeroize();
        entry.password.zeroize();
    }
    for note in &mut vault.notes {
        note.title.zeroize();
        note.content.zeroize();
    }
    vault.entries.clear();
    vault.notes.clear();
    vault.entries.shrink_to_fit();
    vault.notes.shrink_to_fit();
    master_password.zeroize();
}

fn verify_master(master: &str, stored: &str) -> Result<()> {
    let parsed = PasswordHash::new(stored).map_err(|e| anyhow!("Bad stored hash: {e}"))?;
    Argon2::default()
        .verify_password(master.as_bytes(), &parsed)
        .map_err(|_| anyhow!("Password mismatch"))
}

fn persist_vault_with_revision(
    vault_path: &Path,
    vault: &mut Vault,
    master_password: &str,
) -> Result<()> {
    vault.revision = vault.revision.saturating_add(1);
    save_vault(vault_path, vault, master_password)?;
    let _ = store_trusted_revision(vault.revision);
    Ok(())
}

fn verify_loaded_revision(vault: &Vault) -> Result<()> {
    let trusted = match load_trusted_revision() {
        Ok(v) => v,
        Err(_) => return Ok(()),
    };
    match trusted {
        Some(trusted) if vault.revision < trusted => Err(anyhow!(
            "Vault rollback detected (loaded revision {} is older than trusted revision {})",
            vault.revision,
            trusted
        )),
        Some(trusted) if vault.revision > trusted => {
            let _ = store_trusted_revision(vault.revision);
            Ok(())
        }
        Some(_) => Ok(()),
        None => {
            let _ = store_trusted_revision(vault.revision);
            Ok(())
        }
    }
}

fn run_tui_passwords(
    vault: &mut Vault,
    master_password: &mut String,
    vault_path: &std::path::Path,
) -> Result<()> {
    enable_raw_mode()?;
    let mut stdout = std::io::stdout();
    execute!(stdout, EnterAlternateScreen, crossterm::cursor::Hide)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut service_idx: usize = 0;
    let mut entry_idx: usize = 0;
    let mut delete_overlay: Option<String> = None;
    let mut pending_delete: Option<PendingDelete> = None;
    let mut focus_services = true;
    let mut status = PASSWORD_NAV_HINT.to_string();
    let mut status_until: Option<Instant> = None;
    let mut last_activity = Instant::now();
    let mut add_form = AddForm::default();
    let mut change_credential_password_form = ChangeCredentialPasswordForm::default();
    let mut change_form = ChangeMasterForm::default();
    let mut quit_overlay = false;

    let result = (|| -> Result<()> {
        loop {
            if let Some(until) = status_until {
                if Instant::now() >= until {
                    status = PASSWORD_NAV_HINT.to_string();
                    status_until = None;
                }
            }

            if last_activity.elapsed() >= Duration::from_secs(IDLE_TIMEOUT_SECS) {
                status = "Idle timeout reached. Exiting...".to_string();
                terminal.draw(|f| {
                    let services = unique_services(vault);
                    let status_strength = current_status_strength(
                        &add_form,
                        &change_credential_password_form,
                        &change_form,
                    );
                    let detail_strength_override =
                        current_detail_strength_override(&change_credential_password_form);
                    let (overlay, overlay_title) = if change_form.active {
                        (
                            build_change_overlay(&change_form),
                            Some("Change master passphrase".to_string()),
                        )
                    } else if change_credential_password_form.active {
                        (
                            build_change_credential_password_overlay(
                                &change_credential_password_form,
                            ),
                            Some("Change credential password".to_string()),
                        )
                    } else if add_form.active {
                        (build_overlay(&add_form), Some("Add credential".to_string()))
                    } else {
                        (None, None)
                    };
                    let quit_prompt = if quit_overlay {
                        Some(vec![
                            "Quit?".to_string(),
                            "".to_string(),
                            "[y] Yes   [n] No".to_string(),
                        ])
                    } else {
                        None
                    };
                    let view = ViewState {
                        vault,
                        services,
                        service_idx,
                        entry_idx,
                        delete_overlay: delete_overlay.clone(),
                        focus_services,
                        overlay,
                        overlay_title,
                        quit_overlay: quit_prompt,
                        status: status.clone(),
                        status_strength,
                        detail_strength_override,
                    };
                    draw(f, &view);
                })?;
                break;
            }

            terminal.draw(|f| {
                let services = unique_services(vault);
                let status_strength = current_status_strength(
                    &add_form,
                    &change_credential_password_form,
                    &change_form,
                );
                let detail_strength_override =
                    current_detail_strength_override(&change_credential_password_form);
                let (overlay, overlay_title) = if change_form.active {
                    (
                        build_change_overlay(&change_form),
                        Some("Change master passphrase".to_string()),
                    )
                } else if change_credential_password_form.active {
                    (
                        build_change_credential_password_overlay(
                            &change_credential_password_form,
                        ),
                        Some("Change credential password".to_string()),
                    )
                } else if add_form.active {
                    (build_overlay(&add_form), Some("Add credential".to_string()))
                } else {
                    (None, None)
                };
                let quit_prompt = if quit_overlay {
                    Some(vec![
                        "Quit?".to_string(),
                        "".to_string(),
                        "[y] Yes   [n] No".to_string(),
                    ])
                } else {
                    None
                };
                let view = ViewState {
                    vault,
                    services,
                    service_idx,
                    entry_idx,
                    delete_overlay: delete_overlay.clone(),
                    focus_services,
                    overlay,
                    overlay_title,
                    quit_overlay: quit_prompt,
                    status: status.clone(),
                    status_strength,
                    detail_strength_override,
                };
                draw(f, &view);
            })?;

            if event::poll(Duration::from_millis(200))? {
                match event::read()? {
                    Event::Key(key_event) => {
                        last_activity = Instant::now();
                        let previous_status = status.clone();
                        let toggle_visibility = matches!(
                            key_event.code,
                            KeyCode::Char('h') | KeyCode::Char('H')
                        ) && key_event.modifiers.contains(KeyModifiers::CONTROL);
                        if quit_overlay {
                            match key_event.code {
                                KeyCode::Char('y') => break,
                                KeyCode::Char('n') | KeyCode::Esc => quit_overlay = false,
                                _ => {}
                            }
                        } else if delete_overlay.is_some() {
                            match key_event.code {
                                KeyCode::Char('y') => {
                                    if let Some(target) = pending_delete.take() {
                                        match target {
                                            PendingDelete::Credential { idx, service } => {
                                                if idx < vault.entries.len() {
                                                    vault.entries.remove(idx);
                                                }
                                                let services = unique_services(vault);
                                                if let Some(pos) = services.iter().position(|s| s == &service) {
                                                    service_idx = pos.min(services.len().saturating_sub(1));
                                                } else {
                                                    service_idx = service_idx.min(services.len().saturating_sub(1));
                                                }
                                                entry_idx = 0;
                                                persist_vault_with_revision(
                                                    vault_path,
                                                    vault,
                                                    master_password,
                                                )?;
                                                status = "Entry deleted".into();
                                            }
                                            PendingDelete::Service { service } => {
                                                vault.entries.retain(|e| e.name != service);
                                                let services = unique_services(vault);
                                                if services.is_empty() {
                                                    service_idx = 0;
                                                    entry_idx = 0;
                                                } else {
                                                    service_idx = service_idx.min(services.len().saturating_sub(1));
                                                    entry_idx = 0;
                                                }
                                                persist_vault_with_revision(
                                                    vault_path,
                                                    vault,
                                                    master_password,
                                                )?;
                                                status = "Service deleted".into();
                                            }
                                        }
                                    }
                                    delete_overlay = None;
                                }
                                KeyCode::Char('n') | KeyCode::Esc => {
                                    delete_overlay = None;
                                    pending_delete = None;
                                    status = "Delete cancelled".into();
                                }
                                _ => {}
                            }
                        } else if change_credential_password_form.active {
                            handle_change_credential_password_modal(
                                key_event.code,
                                toggle_visibility,
                                &mut change_credential_password_form,
                                vault,
                                master_password,
                                vault_path,
                                &mut status,
                            )?;
                        } else if add_form.active {
                            handle_add_modal(
                                key_event.code,
                                toggle_visibility,
                                &mut add_form,
                                vault,
                                &mut service_idx,
                                &mut entry_idx,
                                &mut status,
                                master_password,
                                vault_path,
                            )?;
                        } else if change_form.active {
                            handle_change_master_modal(
                                key_event.code,
                                toggle_visibility,
                                &mut change_form,
                                vault,
                                master_password,
                                vault_path,
                                &mut status,
                            )?;
                        } else {
                            match key_event.code {
                                KeyCode::Esc => {
                                    quit_overlay = true;
                                }
                                KeyCode::Left => focus_services = true,
                                KeyCode::Right => focus_services = false,
                                KeyCode::Up => {
                                    if focus_services {
                                        let max = unique_services(vault).len().saturating_sub(1);
                                        service_idx = service_idx.saturating_sub(1).min(max);
                                        entry_idx = 0;
                                    } else {
                                        let (_, filtered) = entries_for_service(vault, service_idx);
                                        if !filtered.is_empty() {
                                            entry_idx = entry_idx.saturating_sub(1).min(filtered.len() - 1);
                                        }
                                    }
                                }
                                KeyCode::Down => {
                                    if focus_services {
                                        let max = unique_services(vault).len().saturating_sub(1);
                                        service_idx = (service_idx + 1).min(max);
                                        entry_idx = 0;
                                    } else {
                                        let (_, filtered) = entries_for_service(vault, service_idx);
                                        if !filtered.is_empty() {
                                            entry_idx = (entry_idx + 1).min(filtered.len() - 1);
                                        }
                                    }
                                }
                                KeyCode::Enter | KeyCode::Char('c') => {
                                    let (_, filtered) = entries_for_service(vault, service_idx);
                                    if let Some(entry) = filtered.get(entry_idx) {
                                        match copy_password_to_clipboard(entry) {
                                            Ok(_) => status = format!("Copied '{}' password to clipboard for 20s", entry.name),
                                            Err(e) => status = format!("Clipboard error: {e}"),
                                        }
                                    }
                                }
                                KeyCode::Char('n') => {
                                    add_form = AddForm::default();
                                    add_form.active = true;
                                    add_form.show_password = false;
                                }
                                KeyCode::Char('r') => {
                                    let (services, filtered) = entries_for_service(vault, service_idx);
                                    if filtered.is_empty() {
                                        status = "No credential selected".into();
                                        continue;
                                    }
                                    let selected_entry_idx =
                                        entry_idx.min(filtered.len().saturating_sub(1));
                                    let svc_name = services
                                        .get(service_idx.min(services.len().saturating_sub(1)))
                                        .cloned()
                                        .unwrap_or_default();
                                    if let Some(global_idx) =
                                        nth_entry_index(vault, &svc_name, selected_entry_idx)
                                    {
                                        let label = filtered[selected_entry_idx]
                                            .username
                                            .as_deref()
                                            .unwrap_or(&filtered[selected_entry_idx].email)
                                            .to_string();
                                        change_credential_password_form = ChangeCredentialPasswordForm {
                                            active: true,
                                            target_idx: Some(global_idx),
                                            target_label: label.clone(),
                                            new_password: String::new(),
                                            show_password: false,
                                        };
                                        status = format!(
                                            "Changing credential password for '{label}'"
                                        );
                                    } else {
                                        status = "Credential selection error".into();
                                    }
                                }
                                KeyCode::Char('d') => {
                                    let (services, filtered) = entries_for_service(vault, service_idx);
                                    if focus_services {
                                        let svc_name = services
                                            .get(service_idx.min(services.len().saturating_sub(1)))
                                            .cloned()
                                            .unwrap_or_default();
                                        pending_delete = Some(PendingDelete::Service { service: svc_name.clone() });
                                        delete_overlay = Some(format!("Delete all credentials for '{}'?", svc_name));
                                        status = "Confirm delete with y/n".into();
                                    } else {
                                        if filtered.is_empty() {
                                            status = "No credential to delete".into();
                                            continue;
                                        }
                                        let selected_entry_idx =
                                            entry_idx.min(filtered.len().saturating_sub(1));
                                        let svc_name = services
                                            .get(service_idx.min(services.len().saturating_sub(1)))
                                            .cloned()
                                            .unwrap_or_default();
                                        if let Some(global_idx) =
                                            nth_entry_index(vault, &svc_name, selected_entry_idx)
                                        {
                                            let display = filtered[selected_entry_idx]
                                                .username
                                                .as_deref()
                                                .unwrap_or(&filtered[selected_entry_idx].email);
                                            pending_delete = Some(PendingDelete::Credential { idx: global_idx, service: svc_name });
                                            delete_overlay =
                                                Some(format!("Delete credential '{}'? ", display));
                                            status = "Confirm delete with y/n".into();
                                        }
                                    }
                                }
                                KeyCode::Char('m') => {
                                    change_form = ChangeMasterForm::default();
                                    change_form.active = true;
                                    change_form.show_password = false;
                                    status = "Change master: type new passphrase".into();
                                }
                                _ => {}
                            }
                        }
                        if status != previous_status {
                            if status == PASSWORD_NAV_HINT || status == "Idle timeout reached. Exiting..." {
                                status_until = None;
                            } else {
                                status_until =
                                    Some(Instant::now() + Duration::from_secs(STATUS_MESSAGE_SECS));
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        Ok(())
    })();

    disable_raw_mode().ok();
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        crossterm::cursor::Show
    )
    .ok();
    terminal.show_cursor().ok();

    result
}

fn unique_services(vault: &Vault) -> Vec<String> {
    let mut names: Vec<String> = vault.entries.iter().map(|e| e.name.clone()).collect();
    names.sort();
    names.dedup();
    names
}

fn entries_for_service<'a>(vault: &'a Vault, service_idx: usize) -> (Vec<String>, Vec<&'a Entry>) {
    let services = unique_services(vault);
    if services.is_empty() {
        return (services, Vec::new());
    }
    let selected_service = services[service_idx.min(services.len().saturating_sub(1))].clone();
    let filtered: Vec<&Entry> = vault
        .entries
        .iter()
        .filter(|e| e.name == selected_service)
        .collect();
    (services, filtered)
}

fn nth_entry_index(vault: &Vault, service: &str, nth: usize) -> Option<usize> {
    let mut count = 0;
    for (idx, entry) in vault.entries.iter().enumerate() {
        if entry.name == service {
            if count == nth {
                return Some(idx);
            }
            count += 1;
        }
    }
    None
}

fn handle_text_mode(
    text_path: std::path::PathBuf,
    vault: &mut Vault,
    master_password: &str,
    vault_path: &std::path::Path,
) -> Result<()> {
    let content = std::fs::read_to_string(&text_path)
        .map_err(|e| anyhow!("Failed to read {}: {e}", text_path.display()))?;
    let title = text_path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("note")
        .to_string();

    if let Some(idx) = vault.notes.iter().position(|n| n.title == title) {
        println!("Note '{}' exists. Overwrite? (y/N)", title);
        let mut ans = String::new();
        std::io::stdin().read_line(&mut ans)?;
        if !matches!(ans.trim().to_lowercase().as_str(), "y" | "yes") {
            println!("Cancelled.");
            return Ok(());
        }
        vault.notes[idx].content = content;
    } else {
        vault.notes.push(Note { id: crate::models::new_uuid(), title: title.clone(), content });
    }

    persist_vault_with_revision(vault_path, vault, master_password)?;
    println!("Stored note '{}' in vault.", title);

    Ok(())
}

fn run_tui_notes(
    vault: &mut Vault,
    master_password: &mut String,
    vault_path: &std::path::Path,
) -> Result<()> {
    enable_raw_mode()?;
    let mut stdout = std::io::stdout();
    execute!(stdout, EnterAlternateScreen, crossterm::cursor::Hide)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut note_idx: usize = 0;
    let mut delete_overlay: Option<String> = None;
    let mut delete_idx: Option<usize> = None;
    let mut add_prompt: AddNotePrompt = AddNotePrompt::default();
    let mut status = NOTES_NAV_HINT.to_string();
    let mut status_until: Option<Instant> = None;
    let mut last_activity = Instant::now();
    let mut quit_overlay = false;

    let result = (|| -> Result<()> {
        loop {
            if let Some(until) = status_until {
                if Instant::now() >= until {
                    status = NOTES_NAV_HINT.to_string();
                    status_until = None;
                }
            }

            if last_activity.elapsed() >= Duration::from_secs(IDLE_TIMEOUT_SECS) {
                status = "Idle timeout reached. Exiting...".to_string();
                terminal.draw(|f| {
                    let quit_prompt = if quit_overlay {
                        Some(vec![
                            "Quit?".to_string(),
                            "".to_string(),
                            "[y] Yes   [n] No".to_string(),
                        ])
                    } else {
                        None
                    };
                    let view = NoteViewState {
                        vault,
                        note_idx,
                        delete_overlay: delete_overlay.clone(),
                        add_overlay: build_note_overlay(&add_prompt),
                        status: status.clone(),
                        quit_overlay: quit_prompt,
                    };
                    draw_notes(f, &view);
                })?;
                break;
            }

            terminal.draw(|f| {
                let quit_prompt = if quit_overlay {
                    Some(vec![
                        "Quit?".to_string(),
                        "".to_string(),
                        "[y] Yes   [n] No".to_string(),
                    ])
                } else {
                    None
                };
                let view = NoteViewState {
                    vault,
                    note_idx,
                    delete_overlay: delete_overlay.clone(),
                    add_overlay: build_note_overlay(&add_prompt),
                    status: status.clone(),
                    quit_overlay: quit_prompt,
                };
                draw_notes(f, &view);
            })?;

            if event::poll(Duration::from_millis(200))? {
                match event::read()? {
                    Event::Key(key_event) => {
                        last_activity = Instant::now();
                        let previous_status = status.clone();
                        if quit_overlay {
                            match key_event.code {
                                KeyCode::Char('y') => break,
                                KeyCode::Char('n') | KeyCode::Esc => quit_overlay = false,
                                _ => {}
                            }
                            continue;
                        }
                        if delete_overlay.is_some() {
                            match key_event.code {
                                KeyCode::Char('y') => {
                                    if let Some(idx) = delete_idx.take() {
                                        if idx < vault.notes.len() {
                                            vault.notes.remove(idx);
                                            if note_idx > 0 {
                                                note_idx -= 1;
                                            }
                                            persist_vault_with_revision(
                                                vault_path,
                                                vault,
                                                master_password,
                                            )?;
                                            status = "Note deleted".into();
                                        }
                                    }
                                    delete_overlay = None;
                                }
                                KeyCode::Char('n') | KeyCode::Esc => {
                                    delete_overlay = None;
                                    delete_idx = None;
                                    status = "Delete cancelled".into();
                                }
                                _ => {}
                            }
                            continue;
                        }
                        if add_prompt.active {
                            match key_event.code {
                                KeyCode::Esc => {
                                    add_prompt = AddNotePrompt::default();
                                    status = "Add note cancelled".into();
                                }
                                KeyCode::Backspace => {
                                    add_prompt.title.pop();
                                }
                                KeyCode::Enter => {
                                    let title = add_prompt.title.trim();
                                    if title.is_empty() {
                                        status = "Title required".into();
                                    } else {
                                        let note = Note { id: crate::models::new_uuid(), title: title.to_string(), content: String::new() };
                                        match edit_note_with_editor(note, &mut terminal)? {
                                            Some(updated) => {
                                                vault.notes.push(updated);
                                                persist_vault_with_revision(
                                                    vault_path,
                                                    vault,
                                                    master_password,
                                                )?;
                                                note_idx = vault.notes.len().saturating_sub(1);
                                                status = "Note added".into();
                                            }
                                            None => status = "Editor cancelled".into(),
                                        }
                                        add_prompt = AddNotePrompt::default();
                                    }
                                }
                                KeyCode::Char(c) => {
                                    add_prompt.title.push(c);
                                }
                                _ => {}
                            }
                            continue;
                        }
                        match key_event.code {
                            KeyCode::Esc => quit_overlay = true,
                            KeyCode::Up => {
                                if !vault.notes.is_empty() {
                                    note_idx = note_idx.saturating_sub(1);
                                }
                            }
                            KeyCode::Down => {
                                if !vault.notes.is_empty() {
                                    note_idx = (note_idx + 1).min(vault.notes.len().saturating_sub(1));
                                }
                            }
                            KeyCode::Char('n') => {
                                add_prompt = AddNotePrompt { active: true, title: String::new() };
                                status = "Type note title, Enter to edit".into();
                            }
                            KeyCode::Right => {
                                if let Some(existing) = vault.notes.get(note_idx).cloned() {
                                    let updated = edit_note_with_editor(existing, &mut terminal)?;
                                    if let Some(updated) = updated {
                                        vault.notes[note_idx] = updated;
                                        persist_vault_with_revision(
                                            vault_path,
                                            vault,
                                            master_password,
                                        )?;
                                        status = "Note updated".into();
                                    }
                                }
                            }
                            KeyCode::Char('d') => {
                                if vault.notes.get(note_idx).is_some() {
                                    delete_idx = Some(note_idx);
                                    delete_overlay = Some("Delete note?".into());
                                    status = "Confirm delete with y/n".into();
                                }
                            }
                            KeyCode::Enter | KeyCode::Char('c') => {
                                if let Some(note) = vault.notes.get(note_idx) {
                                    match crate::ui::copy_note_to_clipboard(note) {
                                        Ok(_) => status = format!("Copied note '{}'", note.title),
                                        Err(e) => status = format!("Clipboard error: {e}"),
                                    }
                                }
                            }
                            _ => {}
                        }
                        if status != previous_status {
                            if status == NOTES_NAV_HINT || status == "Idle timeout reached. Exiting..." {
                                status_until = None;
                            } else {
                                status_until =
                                    Some(Instant::now() + Duration::from_secs(STATUS_MESSAGE_SECS));
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        Ok(())
    })();

    disable_raw_mode().ok();
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        crossterm::cursor::Show
    )
    .ok();
    terminal.show_cursor().ok();

    result
}

fn edit_note_with_editor(
    note: Note,
    terminal: &mut Terminal<CrosstermBackend<std::io::Stdout>>,
) -> Result<Option<Note>> {
    disable_raw_mode().ok();
    execute!(terminal.backend_mut(), LeaveAlternateScreen, Show).ok();

    let mut file = NamedTempFile::new()?;
    file.write_all(note.content.as_bytes())?;
    file.flush()?;

    let editor = std::env::var("EDITOR").unwrap_or_else(|_| "nvim".to_string());
    let status = Command::new(editor)
        .arg(file.path())
        .status()
        .map_err(|e| anyhow!("Failed to launch editor: {e}"))?;

    execute!(terminal.backend_mut(), EnterAlternateScreen, Hide).ok();
    enable_raw_mode().ok();
    terminal.clear()?;

    if !status.success() {
        return Ok(None);
    }

    let new_content = fs::read_to_string(file.path())?;
    let updated = Note {
        id: note.id,
        title: note.title,
        content: new_content,
    };
    Ok(Some(updated))
}

#[derive(Default)]
struct AddForm {
    active: bool,
    step: usize,
    name: String,
    username: String,
    email: String,
    notes: String,
    password: String,
    show_password: bool,
}

#[derive(Default)]
struct AddNotePrompt {
    active: bool,
    title: String,
}

#[derive(Default)]
struct ChangeMasterForm {
    active: bool,
    step: usize,
    new1: String,
    new2: String,
    show_password: bool,
}

#[derive(Default)]
struct ChangeCredentialPasswordForm {
    active: bool,
    target_idx: Option<usize>,
    target_label: String,
    new_password: String,
    show_password: bool,
}

fn current_status_strength(
    add_form: &AddForm,
    change_credential_password_form: &ChangeCredentialPasswordForm,
    change_form: &ChangeMasterForm,
) -> Option<StatusStrength> {
    if change_credential_password_form.active {
        Some(classify_password_strength(
            &change_credential_password_form.new_password,
        ))
    } else if change_form.active {
        let current_input = if change_form.step == 0 || change_form.new2.is_empty() {
            &change_form.new1
        } else {
            &change_form.new2
        };
        Some(classify_password_strength(current_input))
    } else if add_form.active {
        Some(classify_password_strength(&add_form.password))
    } else {
        None
    }
}

fn current_detail_strength_override(
    change_credential_password_form: &ChangeCredentialPasswordForm,
) -> Option<StatusStrength> {
    if change_credential_password_form.active {
        Some(classify_password_strength(
            &change_credential_password_form.new_password,
        ))
    } else {
        None
    }
}

fn generate_strong_password(len: usize) -> String {
    let target_len = len.max(12);
    let upper = b"ABCDEFGHJKLMNPQRSTUVWXYZ";
    let lower = b"abcdefghijkmnopqrstuvwxyz";
    let digits = b"23456789";
    let special = b"!@#$%^&*()-_=+[]{};:,.?";

    let mut rng = OsRng;
    let mut chars = vec![
        *upper.choose(&mut rng).expect("upper charset") as char,
        *lower.choose(&mut rng).expect("lower charset") as char,
        *digits.choose(&mut rng).expect("digit charset") as char,
        *special.choose(&mut rng).expect("special charset") as char,
    ];

    let mut all = Vec::with_capacity(upper.len() + lower.len() + digits.len() + special.len());
    all.extend_from_slice(upper);
    all.extend_from_slice(lower);
    all.extend_from_slice(digits);
    all.extend_from_slice(special);

    while chars.len() < target_len {
        chars.push(*all.choose(&mut rng).expect("combined charset") as char);
    }
    chars.shuffle(&mut rng);
    chars.into_iter().collect()
}

fn build_overlay(form: &AddForm) -> Option<Vec<String>> {
    if !form.active {
        return None;
    }
    let password_display = if form.show_password {
        form.password.clone()
    } else {
        "*".repeat(form.password.chars().count())
    };
    let steps = [
        ("Service/app/site", form.name.clone()),
        ("Username (optional)", form.username.clone()),
        ("Email (required)", form.email.clone()),
        ("Notes (optional)", form.notes.clone()),
        ("Password (required)", password_display),
    ];
    let mut lines = Vec::new();
    lines.push("Add credential".to_string());
    lines.push("".to_string());
    for (idx, (label, val)) in steps.iter().enumerate() {
        let marker = if idx == form.step { ">" } else { " " };
        lines.push(format!("{marker} {label}: {val}"));
    }
    lines.push("Enter confirms; ↑/↓ move fields; Tab generates password; Ctrl+h show/hide".to_string());
    Some(lines)
}

fn build_note_overlay(prompt: &AddNotePrompt) -> Option<Vec<String>> {
    if !prompt.active {
        return None;
    }
    Some(vec![
        "New note title".to_string(),
        "".to_string(),
        format!("> {}", prompt.title),
        "".to_string(),
        "Enter to edit in $EDITOR".to_string(),
    ])
}

fn build_change_overlay(form: &ChangeMasterForm) -> Option<Vec<String>> {
    if !form.active {
        return None;
    }
    let mut lines = Vec::new();
    lines.push("Change master passphrase".to_string());
    lines.push("".to_string());
    let fields = [
        (
            "New passphrase",
            if form.show_password {
                form.new1.clone()
            } else {
                "*".repeat(form.new1.chars().count())
            },
        ),
        (
            "Confirm passphrase",
            if form.show_password {
                form.new2.clone()
            } else {
                "*".repeat(form.new2.chars().count())
            },
        ),
    ];
    for (idx, (label, val)) in fields.iter().enumerate() {
        let marker = if idx == form.step { ">" } else { " " };
        lines.push(format!("{marker} {label}: {val}"));
    }
    lines.push("Enter to save; needs 8+, uppercase, number, special char; Ctrl+h show/hide".to_string());
    Some(lines)
}

fn build_change_credential_password_overlay(
    form: &ChangeCredentialPasswordForm,
) -> Option<Vec<String>> {
    if !form.active {
        return None;
    }
    let mut lines = Vec::new();
    lines.push("Change credential password".to_string());
    lines.push("".to_string());
    lines.push(format!("Target: {}", form.target_label));
    let display = if form.show_password {
        form.new_password.clone()
    } else {
        "*".repeat(form.new_password.chars().count())
    };
    lines.push(format!("> New password: {display}"));
    lines.push("Enter to save; Tab generates password; Ctrl+h show/hide".to_string());
    Some(lines)
}

fn handle_add_modal(
    key: KeyCode,
    toggle_visibility: bool,
    form: &mut AddForm,
    vault: &mut Vault,
    service_idx: &mut usize,
    entry_idx: &mut usize,
    status: &mut String,
    master_password: &str,
    vault_path: &std::path::Path,
) -> Result<()> {
    if toggle_visibility && form.step == 4 {
        form.show_password = !form.show_password;
        *status = if form.show_password {
            "Password visibility: visible".into()
        } else {
            "Password visibility: hidden".into()
        };
        return Ok(());
    }

    match key {
        KeyCode::Esc => {
            form.active = false;
            *status = "Add cancelled".into();
            return Ok(());
        }
        KeyCode::Up | KeyCode::BackTab => {
            form.step = form.step.saturating_sub(1);
        }
        KeyCode::Down => {
            form.step = (form.step + 1).min(4);
        }
        KeyCode::Backspace => {
            match form.step {
                0 => { form.name.pop(); }
                1 => { form.username.pop(); }
                2 => { form.email.pop(); }
                3 => { form.notes.pop(); }
                4 => { form.password.pop(); }
                _ => {}
            }
        }
        KeyCode::Tab => {
            if form.step == 4 {
                form.password = generate_strong_password(20);
                *status = "Generated strong password".into();
            }
        }
        KeyCode::Enter => {
            if form.step < 4 {
                form.step += 1;
            } else {
                if form.name.trim().is_empty() || form.email.trim().is_empty() || form.password.is_empty() {
                    *status = "Name, email, and password required".into();
                    return Ok(());
                }
                let entry = Entry {
                    id: crate::models::new_uuid(),
                    name: form.name.trim().to_string(),
                    email: form.email.trim().to_string(),
                    password: form.password.clone(),
                    username: if form.username.trim().is_empty() {
                        None
                    } else {
                        Some(form.username.trim().to_string())
                    },
                    notes: if form.notes.trim().is_empty() {
                        None
                    } else {
                        Some(form.notes.trim().to_string())
                    },
                };
                let svc_name = entry.name.clone();
                vault.entries.push(entry);
                let services_now = unique_services(vault);
                if let Some(idx) = services_now.iter().position(|s| s == &svc_name) {
                    *service_idx = idx;
                    *entry_idx = entries_for_service(vault, *service_idx).1.len().saturating_sub(1);
                }
                persist_vault_with_revision(vault_path, vault, master_password)?;
                *status = format!("Added {svc_name}");
                form.active = false;
                form.step = 0;
                form.name.clear();
                form.username.clear();
                form.email.clear();
                form.notes.clear();
                form.password.clear();
                form.show_password = false;
            }
        }
        KeyCode::Char(c) => {
            match form.step {
                0 => form.name.push(c),
                1 => form.username.push(c),
                2 => form.email.push(c),
                3 => form.notes.push(c),
                4 => form.password.push(c),
                _ => {}
            }
        }
        _ => {}
    }
    Ok(())
}

fn handle_change_master_modal(
    key: KeyCode,
    toggle_visibility: bool,
    form: &mut ChangeMasterForm,
    vault: &mut Vault,
    master_password: &mut String,
    vault_path: &std::path::Path,
    status: &mut String,
) -> Result<()> {
    if toggle_visibility {
        form.show_password = !form.show_password;
        *status = if form.show_password {
            "Passphrase visibility: visible".into()
        } else {
            "Passphrase visibility: hidden".into()
        };
        return Ok(());
    }

    match key {
        KeyCode::Esc => {
            *status = "Change master cancelled".into();
            *form = ChangeMasterForm::default();
        }
        KeyCode::Backspace => {
            match form.step {
                0 => {
                    form.new1.pop();
                }
                1 => {
                    form.new2.pop();
                }
                _ => {}
            }
        }
        KeyCode::Enter => {
            if form.step == 0 {
                form.step = 1;
            } else {
                if form.new1 != form.new2 {
                    *status = "Passphrases do not match".into();
                    return Ok(());
                }
                if let Err(e) = validate_master_passphrase(&form.new1) {
                    *status = e.to_string();
                    return Ok(());
                }
                if form.new1 == *master_password {
                    *status = "Passphrase already in use".into();
                    return Ok(());
                }
                *master_password = form.new1.clone();
                persist_vault_with_revision(vault_path, vault, master_password)?;
                *status = "Master passphrase updated".into();
                *form = ChangeMasterForm::default();
            }
        }
        KeyCode::Char(c) => {
            match form.step {
                0 => form.new1.push(c),
                1 => form.new2.push(c),
                _ => {}
            }
        }
        _ => {}
    }
    Ok(())
}

fn handle_change_credential_password_modal(
    key: KeyCode,
    toggle_visibility: bool,
    form: &mut ChangeCredentialPasswordForm,
    vault: &mut Vault,
    master_password: &str,
    vault_path: &std::path::Path,
    status: &mut String,
) -> Result<()> {
    if toggle_visibility {
        form.show_password = !form.show_password;
        *status = if form.show_password {
            "Password visibility: visible".into()
        } else {
            "Password visibility: hidden".into()
        };
        return Ok(());
    }

    match key {
        KeyCode::Esc => {
            *status = "Credential password change cancelled".into();
            *form = ChangeCredentialPasswordForm::default();
        }
        KeyCode::Backspace => {
            form.new_password.pop();
        }
        KeyCode::Tab => {
            form.new_password = generate_strong_password(20);
            *status = "Generated strong password".into();
        }
        KeyCode::Enter => {
            if form.new_password.is_empty() {
                *status = "Password cannot be empty".into();
                return Ok(());
            }
            let idx = match form.target_idx {
                Some(i) => i,
                None => {
                    *status = "No credential selected".into();
                    *form = ChangeCredentialPasswordForm::default();
                    return Ok(());
                }
            };
            if let Some(entry) = vault.entries.get_mut(idx) {
                if entry.password == form.new_password {
                    *status = "Password already in use".into();
                    return Ok(());
                }
                entry.password = form.new_password.clone();
                persist_vault_with_revision(vault_path, vault, master_password)?;
                *status = "Credential password updated".into();
            } else {
                *status = "Credential no longer exists".into();
            }
            *form = ChangeCredentialPasswordForm::default();
        }
        KeyCode::Char(c) => {
            form.new_password.push(c);
        }
        _ => {}
    }
    Ok(())
}

fn unlock_screen(
    vault_path: &std::path::Path,
    meta_path: &std::path::Path,
    lock_path: &std::path::Path,
) -> Result<(Vault, String)> {
    let mut input = String::new();
    let mut status = "Enter master passphrase to unlock (Ctrl+h show/hide)".to_string();
    let mut attempts: u8 = 0;
    let mut anim_frame: usize = 0;
    let mut show_input = false;
    let mut last_tick = Instant::now();
    let tick = Duration::from_millis(150);

    enable_raw_mode()?;
    let mut stdout = std::io::stdout();
    execute!(stdout, EnterAlternateScreen, crossterm::cursor::Hide)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let result = (|| -> Result<(Vault, String)> {
        loop {
            if last_tick.elapsed() >= tick {
                anim_frame = anim_frame.wrapping_add(1);
                last_tick = Instant::now();
            }
            let input_display = if show_input {
                input.clone()
            } else {
                "•".repeat(input.chars().count())
            };
            terminal.draw(|f| {
                let view = UnlockState {
                    status: status.clone(),
                    input_display: &input_display,
                    input_visible: show_input,
                    anim_frame,
                };
                draw_unlock(f, &view);
            })?;

            if event::poll(Duration::from_millis(200))? {
                match event::read()? {
                    Event::Key(key_event) => {
                        let toggle_visibility = matches!(
                            key_event.code,
                            KeyCode::Char('h') | KeyCode::Char('H')
                        ) && key_event.modifiers.contains(KeyModifiers::CONTROL);
                        if toggle_visibility {
                            show_input = !show_input;
                            status = if show_input {
                                "Enter master passphrase to unlock (visible)".to_string()
                            } else {
                                "Enter master passphrase to unlock (hidden)".to_string()
                            };
                            continue;
                        }
                        match key_event.code {
                            KeyCode::Esc => return Err(anyhow!("Cancelled")),
                            KeyCode::Enter => {
                                let pw = input.clone();
                                match attempt_unlock(vault_path, meta_path, &pw) {
                                    Ok(vault) => return Ok((vault, pw)),
                                    Err(e) => {
                                        attempts = attempts.saturating_add(1);
                                        status = format!("Unlock failed: {e}");
                                        input.clear();
                                        if attempts >= MAX_ATTEMPTS {
                                            teardown_terminal(&mut terminal);
                                            set_lock(lock_path, LOCK_SECONDS)?;
                                        } else {
                                            let left = MAX_ATTEMPTS.saturating_sub(attempts);
                                            status = format!("{status} | Attempts left: {left}");
                                        }
                                    }
                                }
                            }
                            KeyCode::Backspace => {
                                input.pop();
                            }
                            KeyCode::Char(c) => {
                                input.push(c);
                            }
                            _ => {}
                        }
                    }
                    _ => {}
                }
            }
        }
    })();

    teardown_terminal(&mut terminal);
    result
}

fn attempt_unlock(
    vault_path: &std::path::Path,
    meta_path: &std::path::Path,
    password: &str,
) -> Result<Vault> {
    if vault_path.exists() {
        if is_wrapped_vault_file(vault_path)? {
            let vault = load_vault(vault_path, password)?;
            verify_loaded_revision(&vault)?;
            Ok(vault)
        } else if let Some(meta) = load_meta(meta_path)? {
            verify_master(password, &meta.master_hash)?;
            let mut vault = if let Some(legacy_key) = load_wrapped_key()? {
                match load_vault_with_key(vault_path, &legacy_key) {
                    Ok(v) => v,
                    Err(_) => load_vault_legacy(vault_path, password)?,
                }
            } else {
                load_vault_legacy(vault_path, password)?
            };
            persist_vault_with_revision(vault_path, &mut vault, password)?;
            verify_loaded_revision(&vault)?;
            Ok(vault)
        } else {
            let mut vault = load_vault_legacy(vault_path, password)?;
            persist_vault_with_revision(vault_path, &mut vault, password)?;
            verify_loaded_revision(&vault)?;
            Ok(vault)
        }
    } else {
        Err(anyhow!("Vault file not found"))
    }
}

fn initialize_new_vault(
    vault_path: &std::path::Path,
) -> Result<(Vault, String)> {
    println!("Welcome to Vaulty! Let's set your master passphrase.");
    let master = prompt_new_master_password()?;

    let mut vault = Vault::default();
    persist_vault_with_revision(vault_path, &mut vault, &master)?;
    Ok((vault, master))
}

fn teardown_terminal(terminal: &mut Terminal<CrosstermBackend<std::io::Stdout>>) {
    disable_raw_mode().ok();
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        crossterm::cursor::Show
    )
    .ok();
    terminal.show_cursor().ok();
}

fn select_or_init_base_dir() -> Result<std::path::PathBuf> {
    let home = dirs::home_dir().ok_or_else(|| anyhow!("Could not determine home directory"))?;
    if let Some(cfg) = load_config()? {
        let raw = std::path::PathBuf::from(cfg.vault_dir.clone());
        let dir = resolve_vault_dir_under_home(&raw, &home)?;
        if !dir.exists() {
            fs::create_dir_all(&dir)?;
        }
        restrict_dir_if_possible(&dir)?;
        return Ok(dir);
    }
    let default = default_base_dir()?;
    loop {
        println!("Vault directory not set. Enter path (must be inside your home).");
        println!("Press Enter to use default [{}]", default.display());
        print!("> ");
        io::stdout().flush()?;
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        let chosen = input.trim();
        let raw = if chosen.is_empty() {
            default.clone()
        } else if chosen.starts_with('/') {
            std::path::PathBuf::from(chosen)
        } else {
            home.join(chosen)
        };

        let dir = match resolve_vault_dir_under_home(&raw, &home) {
            Ok(path) => path,
            Err(e) => {
                println!("{e}. Try again.");
                continue;
            }
        };

        fs::create_dir_all(&dir)?;
        restrict_dir_if_possible(&dir)?;
        save_config(&dir)?;
        println!("Vault directory set to {}", dir.display());
        return Ok(dir);
    }
}

fn resolve_vault_dir_under_home(raw: &Path, home: &Path) -> Result<std::path::PathBuf> {
    let candidate = if raw.is_absolute() {
        raw.to_path_buf()
    } else {
        home.join(raw)
    };

    if candidate
        .components()
        .any(|c| matches!(c, Component::ParentDir))
    {
        return Err(anyhow!("Path cannot contain '..' traversal components"));
    }
    if !candidate.starts_with(home) {
        return Err(anyhow!("Path must be inside {}", home.display()));
    }

    let home_real = fs::canonicalize(home).unwrap_or_else(|_| home.to_path_buf());
    if candidate.exists() {
        let candidate_real = fs::canonicalize(&candidate)?;
        if !candidate_real.starts_with(&home_real) {
            return Err(anyhow!("Path resolves outside {}", home.display()));
        }
    } else if let Some(parent) = candidate.parent() {
        if parent.exists() {
            let parent_real = fs::canonicalize(parent)?;
            if !parent_real.starts_with(&home_real) {
                return Err(anyhow!("Path parent resolves outside {}", home.display()));
            }
        }
    }
    Ok(candidate)
}

fn restrict_dir_if_possible(path: &std::path::Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = fs::Permissions::from_mode(0o700);
        fs::set_permissions(path, perms)?;
    }
    Ok(())
}

#[cfg(debug_assertions)]
fn run_self_check() -> Result<()> {
    let home = dirs::home_dir().ok_or_else(|| anyhow!("Could not determine home directory"))?;
    let mut warnings = 0u32;
    let mut failures = 0u32;

    println!("Vaulty self-check (development build)");
    println!("Home: {}", home.display());

    let configured = load_config()?;
    let base_dir = match configured {
        Some(cfg) => {
            let raw = std::path::PathBuf::from(cfg.vault_dir);
            match resolve_vault_dir_under_home(&raw, &home) {
                Ok(dir) => {
                    println!("[PASS] Configured vault directory is valid: {}", dir.display());
                    dir
                }
                Err(e) => {
                    println!("[FAIL] Invalid configured vault directory: {e}");
                    failures += 1;
                    default_base_dir()?
                }
            }
        }
        None => {
            let dir = default_base_dir()?;
            println!(
                "[WARN] No config found at {}; using default {}",
                crate::storage::config_path()?.display(),
                dir.display()
            );
            warnings += 1;
            dir
        }
    };

    let vault_file = base_dir.join(crate::storage::VAULT_FILE);
    let meta_file = base_dir.join(crate::storage::META_FILE);
    let lock_file = base_dir.join(crate::storage::LOCK_FILE);

    if base_dir.exists() {
        println!("[PASS] Vault directory exists: {}", base_dir.display());
    } else {
        println!("[WARN] Vault directory does not exist yet: {}", base_dir.display());
        warnings += 1;
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if base_dir.exists() {
            let mode = fs::metadata(&base_dir)?.permissions().mode() & 0o777;
            if mode == 0o700 {
                println!("[PASS] Vault directory permissions are 0o700");
            } else {
                println!("[WARN] Vault directory permissions are {:o}, expected 700", mode);
                warnings += 1;
            }
        }
    }

    if meta_file.exists() {
        match load_meta(&meta_file) {
            Ok(Some(meta)) => {
                if PasswordHash::new(&meta.master_hash).is_ok() {
                    println!("[PASS] Legacy meta file is readable and hash format is valid");
                } else {
                    println!("[FAIL] Legacy meta file hash format is invalid");
                    failures += 1;
                }
            }
            Ok(None) => {
                println!("[WARN] Legacy meta file exists but could not be parsed");
                warnings += 1;
            }
            Err(e) => {
                println!("[WARN] Legacy meta file is not readable: {e}");
                warnings += 1;
            }
        }
    }

    let trusted_revision = match load_trusted_revision() {
        Ok(v) => v,
        Err(e) => {
            println!("[WARN] Could not read trusted revision from keyring: {e}");
            warnings += 1;
            None
        }
    };
    if let Some(rev) = trusted_revision {
        println!("[PASS] Trusted revision in keyring: {rev}");
    } else {
        println!("[WARN] Trusted revision is missing in keyring");
        warnings += 1;
    }

    if lock_file.exists() {
        match crate::storage::load_lock(&lock_file) {
            Ok(Some(until)) => println!("[PASS] Lock file is readable (unlock_at={until})"),
            Ok(None) => println!("[WARN] Lock file exists but no lock state found"),
            Err(e) => {
                println!("[FAIL] Lock file is invalid: {e}");
                failures += 1;
            }
        }
    }

    if vault_file.exists() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&vault_file)?.permissions().mode() & 0o777;
            if mode == 0o600 {
                println!("[PASS] Vault file permissions are 0o600");
            } else {
                println!("[WARN] Vault file permissions are {:o}, expected 600", mode);
                warnings += 1;
            }
        }

        if is_wrapped_vault_file(&vault_file)? {
            println!("[PASS] Vault format is wrapped-key v2");
            let passphrase =
                rpassword::prompt_password("Passphrase for decrypt test (leave empty to skip): ")?;
            if passphrase.trim().is_empty() {
                println!("[WARN] Decrypt test skipped");
                warnings += 1;
            } else {
                match load_vault(&vault_file, &passphrase) {
                    Ok(vault) => {
                        println!(
                            "[PASS] Vault decrypts successfully (revision={}, entries={}, notes={})",
                            vault.revision,
                            vault.entries.len(),
                            vault.notes.len()
                        );
                        if let Some(rev) = trusted_revision {
                            if vault.revision < rev {
                                println!(
                                    "[FAIL] Rollback detected: vault revision {} < trusted {}",
                                    vault.revision, rev
                                );
                                failures += 1;
                            } else {
                                println!("[PASS] Revision check passed");
                            }
                        }
                    }
                    Err(e) => {
                        println!("[FAIL] Vault decrypt/read failed: {e}");
                        failures += 1;
                    }
                }
            }
        } else {
            println!("[WARN] Vault appears to be legacy format (migration recommended)");
            warnings += 1;
            match load_wrapped_key() {
                Ok(Some(legacy_key)) => match load_vault_with_key(&vault_file, &legacy_key) {
                    Ok(vault) => {
                        println!(
                            "[PASS] Legacy vault decrypts with keyring key (entries={}, notes={})",
                            vault.entries.len(),
                            vault.notes.len()
                        );
                    }
                    Err(e) => {
                        println!("[FAIL] Legacy vault decrypt failed: {e}");
                        failures += 1;
                    }
                },
                Ok(None) => {
                    println!("[WARN] Legacy vault key missing from keyring");
                    warnings += 1;
                }
                Err(e) => {
                    println!("[WARN] Legacy keyring read failed: {e}");
                    warnings += 1;
                }
            }
        }
    } else {
        println!("[WARN] Vault file does not exist yet: {}", vault_file.display());
        warnings += 1;
    }

    println!("Self-check complete: {failures} failure(s), {warnings} warning(s).");
    if failures > 0 {
        Err(anyhow!("Self-check failed"))
    } else {
        Ok(())
    }
}

fn print_usage(bin_name: &str) {
    eprintln!("Usage: {bin_name} [OPTIONS]");
    eprintln!("  -p, --passwords         Open password vault UI");
    eprintln!("  -n, --notes             Open notes UI");
    eprintln!("  -g, --generate          Generate and print a strong password");
    eprintln!("  -t, --text <PATH>       Import a text file as a note");
    #[cfg(debug_assertions)]
    eprintln!("      --self-check        Run integrity checks");
    eprintln!("  -V, --version           Show version and exit");
}

fn executable_name() -> String {
    let fallback = "vaulty".to_string();
    let arg0 = match std::env::args().next() {
        Some(v) => v,
        None => return fallback,
    };
    let path = Path::new(&arg0);
    match path.file_name().and_then(|name| name.to_str()) {
        Some(name) if !name.is_empty() => name.to_string(),
        _ => fallback,
    }
}

enum PendingDelete {
    Credential { idx: usize, service: String },
    Service { service: String },
}
