use std::io::{self, Write};
use std::thread;
use std::time::Duration;

use anyhow::{anyhow, Result};
use arboard::Clipboard;
use crossterm::terminal::{disable_raw_mode, enable_raw_mode};
use ratatui::{
    prelude::*,
    style::Style,
    widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph, Wrap},
    Frame,
};
// big text banner is rendered via Paragraph using block characters
use rpassword::prompt_password;

use crate::models::{Entry, Note, Vault};

const CLIPBOARD_LIFETIME_SECS: u64 = 20;
const COLOR_SAND: Color = Color::Rgb(0xEB, 0xDB, 0xB2);
const COLOR_OLIVE: Color = Color::Rgb(0x98, 0x97, 0x1A); // kept for future accents
const COLOR_MOSS: Color = Color::Rgb(0x67, 0x67, 0x1C);

#[derive(Clone, Copy)]
struct OverlayTheme {
    border: Color,
    title: Color,
    text: Color,
    bg: Color,
}

fn themed_overlay(title: &str) -> OverlayTheme {
    match title {
        "Add credential" => OverlayTheme {
            border: COLOR_OLIVE,
            title: COLOR_SAND,
            text: COLOR_SAND,
            bg: Color::Rgb(0x1D, 0x21, 0x10),
        },
        "Change master passphrase" => OverlayTheme {
            border: COLOR_MOSS,
            title: Color::Rgb(0xD8, 0xCB, 0xA6),
            text: COLOR_SAND,
            bg: Color::Rgb(0x16, 0x19, 0x0D),
        },
        "Change credential password" => OverlayTheme {
            border: Color::Rgb(0xB3, 0xB2, 0x3A),
            title: COLOR_OLIVE,
            text: COLOR_SAND,
            bg: Color::Rgb(0x20, 0x23, 0x12),
        },
        "Add note" => OverlayTheme {
            border: Color::Rgb(0x86, 0x86, 0x35),
            title: COLOR_SAND,
            text: Color::Rgb(0xE3, 0xD5, 0xAE),
            bg: Color::Rgb(0x1A, 0x1D, 0x12),
        },
        "Confirm delete" => OverlayTheme {
            border: Color::Rgb(0xB3, 0x88, 0x45),
            title: Color::Rgb(0xF0, 0xD8, 0xA8),
            text: COLOR_SAND,
            bg: Color::Rgb(0x2A, 0x1C, 0x11),
        },
        "Confirm quit" => OverlayTheme {
            border: Color::Rgb(0xA7, 0xA2, 0x36),
            title: Color::Rgb(0xE6, 0xD8, 0xB2),
            text: COLOR_SAND,
            bg: Color::Rgb(0x25, 0x24, 0x13),
        },
        _ => OverlayTheme {
            border: COLOR_MOSS,
            title: COLOR_SAND,
            text: COLOR_SAND,
            bg: Color::Rgb(0x1E, 0x20, 0x12),
        },
    }
}

fn centered_overlay_area(frame_size: Rect, lines: &[String]) -> Rect {
    let maxw = lines.iter().map(|s| s.len()).max().unwrap_or(0) as u16 + 4;
    let maxh = lines.len() as u16 + 2;
    Rect::new(
        (frame_size.width.saturating_sub(maxw)) / 2,
        (frame_size.height.saturating_sub(maxh)) / 2,
        maxw.min(frame_size.width),
        maxh.min(frame_size.height),
    )
}

fn render_overlay(f: &mut Frame<'_>, lines: &[String], title: &str) {
    let area = centered_overlay_area(f.size(), lines);
    let theme = themed_overlay(title);
    let paragraph = Paragraph::new(
        lines
            .iter()
            .map(|l| Line::from(l.as_str()))
            .collect::<Vec<Line>>(),
    )
    .style(Style::default().fg(theme.text).bg(theme.bg))
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(Span::styled(
                title,
                Style::default()
                    .fg(theme.title)
                    .add_modifier(Modifier::BOLD),
            ))
            .border_style(
                Style::default()
                    .fg(theme.border)
                    .add_modifier(Modifier::BOLD),
            )
            .style(Style::default().bg(theme.bg)),
    );
    f.render_widget(Clear, area);
    f.render_widget(paragraph, area);
}

const ASCII_BANNER: [&str; 6] = [
    "██╗   ██╗ █████╗ ██╗   ██╗██╗  ████████╗██╗   ██╗",
    "██║   ██║██╔══██╗██║   ██║██║  ╚══██╔══╝╚██╗ ██╔╝",
    "██║   ██║███████║██║   ██║██║     ██║    ╚████╔╝ ",
    "╚██╗ ██╔╝██╔══██║██║   ██║██║     ██║     ╚██╔╝  ",
    " ╚████╔╝ ██║  ██║╚██████╔╝███████╗██║      ██║   ",
    "  ╚═══╝  ╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝      ╚═╝   ",
];

const VAULT_FRAMES: [&[&str]; 5] = [
    &[
        "   ┌─────────┐   ",
        "   │ ╔═════╗ │   ",
        "   │ ║  ●  ║ │   ",
        "   │ ║ [●] ║ │   ",
        "   │ ╚═════╝ │   ",
        "   └─────────┘   ",
    ],
    &[
        "   ┌─────────┐   ",
        "   │ ╔═════╗ │   ",
        "   │ ║  ●  ║ │   ",
        "   │ ║ [ ) ║ │   ",
        "   │ ╚═════╝ │   ",
        "   └─────────┘   ",
    ],
    &[
        "   ┌─────────┐   ",
        "   │ ╔═════╗ │   ",
        "   │ ║  ●  ║ │   ",
        "   │ ║  )  ║ │   ",
        "   │ ╚═════╝ │   ",
        "   └─────────┘   ",
    ],
    &[
        "   ┌─────────┐   ",
        "   │ ╔═════╗ │   ",
        "   │ ║  ●  ║ │   ",
        "   │ ║   ) ║ │   ",
        "   │ ╚═════╝ │   ",
        "   └─────────┘   ",
    ],
    &[
        "   ┌─────────┐   ",
        "   │ ╔═════╗ │   ",
        "   │ ║  ●  ║ │   ",
        "   │ ║    )║ │   ",
        "   │ ╚═════╝ │   ",
        "   └─────────┘   ",
    ],
];

pub struct ViewState<'a> {
    pub vault: &'a Vault,
    pub services: Vec<String>,
    pub service_idx: usize,
    pub entry_idx: usize,
    pub focus_services: bool,
    pub delete_overlay: Option<String>,
    pub overlay: Option<Vec<String>>,
    pub overlay_title: Option<String>,
    pub quit_overlay: Option<Vec<String>>,
    pub status: String,
    pub status_strength: Option<StatusStrength>,
    pub detail_strength_override: Option<StatusStrength>,
}

pub struct UnlockState<'a> {
    pub status: String,
    pub input_display: &'a str,
    pub input_visible: bool,
    pub anim_frame: usize,
}

pub struct NoteViewState<'a> {
    pub vault: &'a Vault,
    pub note_idx: usize,
    pub delete_overlay: Option<String>,
    pub add_overlay: Option<Vec<String>>,
    pub status: String,
    pub quit_overlay: Option<Vec<String>>,
}

#[derive(Clone)]
pub struct StatusStrength {
    pub label: String,
    pub level: u8,
}

pub fn classify_password_strength(password: &str) -> StatusStrength {
    let len = password.chars().count();
    if len < 8 {
        return StatusStrength {
            label: "Weak".to_string(),
            level: 1,
        };
    }

    let has_lower = password.chars().any(|c| c.is_ascii_lowercase());
    let has_upper = password.chars().any(|c| c.is_ascii_uppercase());
    let has_digit = password.chars().any(|c| c.is_ascii_digit());
    let has_special = password
        .chars()
        .any(|c| !c.is_ascii_alphanumeric() && !c.is_whitespace());

    let mut score = 0u8;
    if has_lower {
        score += 1;
    }
    if has_upper {
        score += 1;
    }
    if has_digit {
        score += 1;
    }
    if has_special {
        score += 1;
    }
    if len >= 8 {
        score += 1;
    }
    if len >= 12 {
        score += 1;
    }
    if len >= 16 {
        score += 1;
    }
    if len >= 20 {
        score += 1;
    }

    let (label, level) = match score {
        0..=3 => ("Weak", 1),
        4..=5 => ("Average", 2),
        6..=7 => ("Strong", 3),
        _ => ("Excellent", 4),
    };

    StatusStrength {
        label: label.to_string(),
        level,
    }
}

fn strength_color(level: u8) -> Color {
    match level.clamp(1, 4) {
        1 => Color::Red,
        2 => Color::Yellow,
        3 => Color::Green,
        _ => Color::Cyan,
    }
}

pub fn draw(f: &mut Frame<'_>, state: &ViewState) {
    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(1), Constraint::Length(3)])
        .split(f.size());

    let body = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(30), // services
            Constraint::Percentage(30), // creds
            Constraint::Percentage(40), // detail
        ])
        .split(layout[0]);

    // Services list
    let services_items: Vec<ListItem> = if state.services.is_empty() {
        vec![ListItem::new("No services")]
    } else {
        state
            .services
            .iter()
            .map(|s| ListItem::new(s.clone()))
            .collect()
    };
    let mut svc_state = ListState::default();
    if !state.services.is_empty() {
        svc_state.select(Some(state.service_idx.min(state.services.len() - 1)));
    }
    let svc_list = List::new(services_items)
        .block(Block::default().title("Services").borders(Borders::ALL))
        .highlight_symbol("▶ ")
        .highlight_style(if state.focus_services {
            Style::default()
                .fg(Color::Cyan)
                .bg(Color::Rgb(40, 40, 40))
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default()
                .fg(Color::DarkGray)
        });
    f.render_stateful_widget(svc_list, body[0], &mut svc_state);

    // Entries under selected service
    let current_service = state
        .services
        .get(state.service_idx.min(state.services.len().saturating_sub(1)))
        .cloned()
        .unwrap_or_else(|| "None".into());
    let filtered: Vec<&Entry> = state
        .vault
        .entries
        .iter()
        .filter(|e| e.name == current_service)
        .collect();

    let entry_items: Vec<ListItem> = if filtered.is_empty() {
        vec![ListItem::new("No credentials")]
    } else {
        filtered
            .iter()
            .map(|e| {
                let user = e
                    .username
                    .as_deref()
                    .unwrap_or_else(|| if e.email.is_empty() { "-" } else { &e.email });
                let strength = classify_password_strength(&e.password);
                let color = strength_color(strength.level);
                ListItem::new(Line::from(vec![
                    Span::raw(format!("{user} ({}) ", e.email)),
                    Span::styled(
                        format!("[{}]", strength.label),
                        Style::default().fg(color).add_modifier(Modifier::BOLD),
                    ),
                ]))
            })
            .collect()
    };

    let mut entry_state = ListState::default();
    if !filtered.is_empty() {
        entry_state.select(Some(state.entry_idx.min(filtered.len() - 1)));
    }
    let entry_list = List::new(entry_items)
        .block(Block::default().title("Credentials").borders(Borders::ALL))
        .highlight_symbol("▶ ")
        .highlight_style(if !state.focus_services {
            Style::default()
                .fg(Color::Yellow)
                .bg(Color::Rgb(40, 40, 40))
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::DarkGray)
        });
    f.render_stateful_widget(entry_list, body[1], &mut entry_state);

    // Detail pane
    let detail_block = Block::default()
        .title(format!("Details: {current_service}"))
        .borders(Borders::ALL);
    let detail_lines = if let Some(entry) = filtered.get(state.entry_idx.min(filtered.len().saturating_sub(1))) {
        let user = entry.username.as_deref().unwrap_or("-");
        let notes = entry.notes.as_deref().unwrap_or("-");
        let strength = state
            .detail_strength_override
            .clone()
            .unwrap_or_else(|| classify_password_strength(&entry.password));
        let color = strength_color(strength.level);
        vec![
            Line::from(format!("Service: {}", entry.name)),
            Line::from(format!("Username: {user}")),
            Line::from(format!("Email: {}", entry.email)),
            Line::from(format!("Notes: {notes}")),
            Line::from(vec![
                Span::raw("Strength: "),
                Span::styled(
                    strength.label,
                    Style::default().fg(color).add_modifier(Modifier::BOLD),
                ),
            ]),
            Line::from("Password: (hidden)"),
        ]
    } else {
        vec![Line::from("No credential selected.")]
    };
    let detail = Paragraph::new(detail_lines).wrap(Wrap { trim: true }).block(detail_block);
    f.render_widget(detail, body[2]);

    let footer_line = if let Some(strength) = &state.status_strength {
        let level = strength.level.clamp(1, 4);
        let color = strength_color(level);
        let total = 12usize;
        let filled = (level as usize) * 3;
        let filled = filled.min(total);
        let empty = total.saturating_sub(filled);
        Line::from(vec![
            Span::raw("Strength: "),
            Span::styled(
                strength.label.clone(),
                Style::default().fg(color).add_modifier(Modifier::BOLD),
            ),
            Span::raw(" "),
            Span::raw("["),
            Span::styled("=".repeat(filled), Style::default().fg(color)),
            Span::styled("-".repeat(empty), Style::default().fg(Color::DarkGray)),
            Span::raw("]"),
        ])
    } else {
        Line::from(state.status.clone())
    };
    let footer = Paragraph::new(footer_line).block(Block::default().borders(Borders::ALL));
    f.render_widget(footer, layout[1]);

    if let Some(lines) = &state.overlay {
        let title = state.overlay_title.as_deref().unwrap_or("Overlay");
        render_overlay(f, lines, title);
    }

    if let Some(lines) = &state.quit_overlay {
        render_overlay(f, lines, "Confirm quit");
    }

    if let Some(msg) = &state.delete_overlay {
        let text = vec![
            msg.clone(),
            "".to_string(),
            "[y] Yes   [n] No".to_string(),
        ];
        render_overlay(f, &text, "Confirm delete");
    }
}

pub fn draw_unlock(f: &mut Frame<'_>, state: &UnlockState) {
    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(6),  // top padding
            Constraint::Length(8),  // banner area
            Constraint::Length(6),  // input area
            Constraint::Length(6),  // animation area
            Constraint::Min(0),     // spacer
            Constraint::Length(3),  // footer
        ])
        .split(f.size());

    // Large colored banner centered horizontally
    let banner_lines: Vec<Line> = ASCII_BANNER
        .iter()
        .map(|l| {
            let spans: Vec<Span> = l
                .chars()
                .map(|ch| {
                    let color = match ch {
                        '█' => COLOR_SAND,     // blocks in EBDBB2
                        '═' | '_' => COLOR_OLIVE, // bars/underscores in 98971A
                        '║' => COLOR_MOSS,     // verticals in 67671C
                        _ => Color::Reset,
                    };
                    Span::styled(ch.to_string(), Style::default().fg(color).add_modifier(Modifier::BOLD))
                })
                .collect();
            Line::from(spans)
        })
        .collect();
    let banner = Paragraph::new(banner_lines)
        .alignment(Alignment::Center)
        .block(Block::default().borders(Borders::NONE));
    f.render_widget(banner, layout[1]);

    // Centered narrow input box with label inside input area
    let box_width: u16 = 40;
    let input_area = layout[2];
    let w = box_width.min(input_area.width);
    let x = input_area.x + input_area.width.saturating_sub(w) / 2;
    let label_area = Rect::new(x, input_area.y, w, 1);
    let box_area = Rect::new(x, input_area.y + 1, w, 3);

    let label = Paragraph::new("Enter the passphrase")
        .alignment(Alignment::Center)
        .style(Style::default().fg(COLOR_SAND).add_modifier(Modifier::BOLD));
    f.render_widget(label, label_area);

    let prompt = Paragraph::new(Span::styled(
        format!("> {}", state.input_display),
        Style::default().fg(COLOR_SAND),
    ))
    .alignment(Alignment::Left)
    .block(
        Block::default().borders(Borders::ALL).title(if state.input_visible {
            "Passphrase (visible)"
        } else {
            "Passphrase (hidden)"
        }),
    );
    f.render_widget(prompt, box_area);

    let footer =
        Paragraph::new(state.status.clone()).block(Block::default().borders(Borders::ALL));
    f.render_widget(footer, layout[5]);

    // Animation beneath the input box
    let anim = VAULT_FRAMES[state.anim_frame % VAULT_FRAMES.len()];
    let anim_width: u16 = anim.iter().map(|l| l.len() as u16).max().unwrap_or(0);
    let anim_height: u16 = anim.len() as u16;
    let area = layout[3];
    let x = area.x + area.width.saturating_sub(anim_width) / 2;
    let y = area.y + area.height.saturating_sub(anim_height) / 2;
    let anim_area = Rect::new(x, y, anim_width, anim_height);
    let anim_lines: Vec<Line> = anim
        .iter()
        .map(|l| Line::from(Span::styled(*l, Style::default().fg(COLOR_SAND))))
        .collect();
    let anim_paragraph = Paragraph::new(anim_lines).alignment(Alignment::Center);
    f.render_widget(anim_paragraph, anim_area);
}

pub fn draw_notes(f: &mut Frame<'_>, state: &NoteViewState) {
    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(1), Constraint::Length(3)])
        .split(f.size());

    let body = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(35), Constraint::Percentage(65)])
        .split(layout[0]);

    // Notes list
    let items: Vec<ListItem> = if state.vault.notes.is_empty() {
        vec![ListItem::new("No notes")]
    } else {
        state
            .vault
            .notes
            .iter()
            .map(|n| ListItem::new(n.title.clone()))
            .collect()
    };
    let mut list_state = ListState::default();
    if !state.vault.notes.is_empty() {
        list_state.select(Some(state.note_idx.min(state.vault.notes.len() - 1)));
    }
    let list = List::new(items)
        .block(Block::default().title("Notes").borders(Borders::ALL))
        .highlight_symbol("▶ ")
        .highlight_style(
            Style::default()
                .fg(Color::Cyan)
                .bg(Color::Rgb(40, 40, 40))
                .add_modifier(Modifier::BOLD),
        );
    f.render_stateful_widget(list, body[0], &mut list_state);

    // Detail
    let detail_block = Block::default().title("Content").borders(Borders::ALL);
    let detail_text = if let Some(note) = state.vault.notes.get(state.note_idx.min(state.vault.notes.len().saturating_sub(1))) {
        format!("Title: {}\n\n{}", note.title, note.content)
    } else {
        "No note selected.".to_string()
    };
    let detail = Paragraph::new(detail_text).wrap(Wrap { trim: true }).block(detail_block);
    f.render_widget(detail, body[1]);

    let footer = Paragraph::new(state.status.clone()).block(Block::default().borders(Borders::ALL));
    f.render_widget(footer, layout[1]);

    if let Some(lines) = &state.add_overlay {
        render_overlay(f, lines, "Add note");
    }

    if let Some(msg) = &state.delete_overlay {
        let text = vec![msg.clone(), "".to_string(), "[y] Yes   [n] No".to_string()];
        render_overlay(f, &text, "Confirm delete");
    }

    if let Some(lines) = &state.quit_overlay {
        render_overlay(f, lines, "Confirm quit");
    }
}

pub fn copy_password_to_clipboard(entry: &Entry) -> Result<()> {
    let mut clipboard = Clipboard::new().map_err(|e| anyhow!("Clipboard unavailable: {e}"))?;
    clipboard
        .set_text(entry.password.clone())
        .map_err(|e| anyhow!("Failed to set clipboard: {e}"))?;
    let mut clip = clipboard;
    thread::spawn(move || {
        thread::sleep(Duration::from_secs(CLIPBOARD_LIFETIME_SECS));
        let _ = clip.set_text(String::new());
    });
    Ok(())
}

pub fn prompt_new_entry() -> Result<Entry> {
    disable_raw_mode().ok();
    let size = crossterm::terminal::size().unwrap_or((80, 24));
    let width = 52u16.min(size.0);
    let xpad = (size.0.saturating_sub(width)) / 2;
    let left = " ".repeat(xpad as usize);
    let border = "─".repeat(width as usize - 2);

    println!("{left}┌{border}┐");
    println!(
        "{left}│ {:<pad$}│",
        "Add credential (service/app/site) — q cancels",
        pad = (width as usize - 3)
    );
    println!("{left}├{border}┤");

    print!("{left}│ Service/app/site: ");
    io::stdout().flush()?;
    let mut name = String::new();
    io::stdin().read_line(&mut name)?;
    if name.trim().eq_ignore_ascii_case("q") {
        enable_raw_mode().ok();
        return Err(anyhow!("cancelled"));
    }

    print!("{left}│ Username (optional): ");
    io::stdout().flush()?;
    let mut username = String::new();
    io::stdin().read_line(&mut username)?;

    print!("{left}│ Email (required): ");
    io::stdout().flush()?;
    let mut email = String::new();
    io::stdin().read_line(&mut email)?;
    if email.trim().eq_ignore_ascii_case("q") || email.trim().is_empty() {
        enable_raw_mode().ok();
        return Err(anyhow!("cancelled"));
    }

    print!("{left}│ Notes (optional): ");
    io::stdout().flush()?;
    let mut notes = String::new();
    io::stdin().read_line(&mut notes)?;

    let prompt_pw = format!("{left}│ Password (hidden): ");
    let password = prompt_password(prompt_pw.as_str())?;
    if password.trim().eq_ignore_ascii_case("q") || password.is_empty() {
        enable_raw_mode().ok();
        return Err(anyhow!("cancelled"));
    }

    println!("{left}└{border}┘");
    enable_raw_mode().ok();

    Ok(Entry {
        id: crate::models::new_uuid(),
        name: name.trim().to_string(),
        email: email.trim().to_string(),
        password,
        username: to_opt(username),
        notes: to_opt(notes),
    })
}

pub fn prompt_confirm_delete(name: &str) -> Result<bool> {
    disable_raw_mode().ok();
    print!("Delete '{name}'? (y/N): ");
    io::stdout().flush()?;
    let mut ans = String::new();
    io::stdin().read_line(&mut ans)?;
    enable_raw_mode().ok();
    Ok(matches!(ans.trim().to_lowercase().as_str(), "y" | "yes"))
}

pub fn prompt_new_master_password() -> Result<String> {
    disable_raw_mode().ok();
    let pw = loop {
        let p1 = prompt_password("Set a master password: ")?;
        let p2 = prompt_password("Confirm master password: ")?;
        if p1 == p2 {
            if let Err(e) = validate_master_passphrase(&p1) {
                println!("{e}");
                continue;
            }
            break p1;
        } else {
            println!("Passwords did not match, try again.");
        }
    };
    enable_raw_mode().ok();
    Ok(pw)
}

pub fn prompt_change_master_password() -> Result<String> {
    disable_raw_mode().ok();
    let p1 = prompt_password("New master password: ")?;
    let p2 = prompt_password("Confirm new master password: ")?;
    enable_raw_mode().ok();
    if p1 != p2 {
        Err(anyhow!("Passwords did not match"))
    } else {
        validate_master_passphrase(&p1)?;
        Ok(p1)
    }
}

pub fn validate_master_passphrase(passphrase: &str) -> Result<()> {
    if passphrase.len() < 8 {
        return Err(anyhow!("Password should be at least 8 characters."));
    }
    if !passphrase.chars().any(|c| c.is_ascii_uppercase()) {
        return Err(anyhow!("Password should include at least one uppercase letter."));
    }
    if !passphrase.chars().any(|c| c.is_ascii_digit()) {
        return Err(anyhow!("Password should include at least one number."));
    }
    if !passphrase
        .chars()
        .any(|c| !c.is_alphanumeric() && !c.is_whitespace())
    {
        return Err(anyhow!(
            "Password should include at least one special character."
        ));
    }
    Ok(())
}

fn to_opt(s: String) -> Option<String> {
    let t = s.trim().to_string();
    if t.is_empty() {
        None
    } else {
        Some(t)
    }
}

pub fn prompt_note(existing: Option<Note>) -> Result<Option<Note>> {
    disable_raw_mode().ok();
    let mut title = existing.as_ref().map(|n| n.title.clone()).unwrap_or_default();
    let mut content = existing.as_ref().map(|n| n.content.clone()).unwrap_or_default();

    println!("\nEdit note (leave title empty to cancel)");
    print!("Title [{}]: ", title);
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let input = input.trim();
    if !input.is_empty() {
        title = input.to_string();
    }
    if title.trim().is_empty() {
        enable_raw_mode().ok();
        return Ok(None);
    }

    println!("Content (end with a single line containing only . on its own):");
    if !content.is_empty() {
        println!("(Existing content will be replaced)");
    }
    let mut lines = Vec::new();
    loop {
        let mut line = String::new();
        io::stdin().read_line(&mut line)?;
        let trimmed = line.trim_end();
        if trimmed == "." {
            break;
        }
        lines.push(line);
    }
    if !lines.is_empty() {
        content = lines.join("");
    }

    enable_raw_mode().ok();
    Ok(Some(Note { id: crate::models::new_uuid(), title, content }))
}

pub fn copy_note_to_clipboard(note: &Note) -> Result<()> {
    let mut clipboard = Clipboard::new().map_err(|e| anyhow!("Clipboard unavailable: {e}"))?;
    clipboard
        .set_text(note.content.clone())
        .map_err(|e| anyhow!("Failed to set clipboard: {e}"))?;
    let mut clip = clipboard;
    thread::spawn(move || {
        thread::sleep(Duration::from_secs(CLIPBOARD_LIFETIME_SECS));
        let _ = clip.set_text(String::new());
    });
    Ok(())
}
