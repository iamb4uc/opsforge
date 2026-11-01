use crate::{
    rebuild::{ReviewMode, rebuild},
    verify::verify,
};
use anyhow::{Result, bail};
use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use ratatui::{
    text::Line,
    widgets::{Block, Borders, Paragraph},
};
use std::{io::IsTerminal, path::Path};

#[derive(Clone, Default)]
struct Form {
    source: String,
    output: String,
    linked: bool,
    allow_unverified: bool,
    selected: usize,
    editing: bool,
}

impl Form {
    fn edit(&mut self, key: KeyCode) {
        let value = if self.selected == 0 {
            &mut self.source
        } else {
            &mut self.output
        };
        match key {
            KeyCode::Char(c) if !c.is_control() => value.push(c),
            KeyCode::Backspace => {
                value.pop();
            }
            KeyCode::Enter | KeyCode::Esc => self.editing = false,
            _ => {}
        }
    }

    fn run(&self) -> Result<String> {
        if self.source.is_empty() {
            bail!("enter the source case path");
        }
        if self.selected == 4 {
            let result = verify(Path::new(&self.source))?;
            return Ok(serde_json::to_string_pretty(&result)?);
        }
        if self.output.is_empty() {
            bail!("enter a new output directory");
        }
        let mode = if self.linked {
            ReviewMode::Linked
        } else {
            ReviewMode::Bundle
        };
        let output = rebuild(
            Path::new(&self.source),
            Path::new(&self.output),
            mode,
            self.allow_unverified,
        )?;
        Ok(format!(
            "Review saved: {}\nOpen dashboard/index.html in that directory.",
            output.display()
        ))
    }
}

struct Restore;
impl Drop for Restore {
    fn drop(&mut self) {
        ratatui::restore();
    }
}

struct Pending(Option<std::thread::JoinHandle<Result<String>>>);
impl Drop for Pending {
    fn drop(&mut self) {
        if let Some(handle) = self.0.take() {
            match handle.join() {
                Ok(Ok(_)) => {}
                Ok(Err(error)) => eprintln!("Review failed: {error:#}"),
                Err(_) => eprintln!("Review worker panicked"),
            }
        }
    }
}

/// Configure and run saved-case operations without acquisition or elevation.
pub fn run() -> Result<()> {
    if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
        bail!("review needs a terminal; use verify or rebuild for automation");
    }
    let mut terminal = ratatui::init();
    let _restore = Restore;
    let mut form = Form::default();
    let mut message = String::new();
    let mut pending = Pending(None);
    loop {
        if pending
            .0
            .as_ref()
            .is_some_and(|handle| handle.is_finished())
            && let Some(handle) = pending.0.take()
        {
            message = match handle.join() {
                Ok(Ok(value)) => value,
                Ok(Err(error)) => format!("Failed: {error:#}"),
                Err(_) => "Failed: review worker panicked; inspect any partial output.".into(),
            };
        }
        terminal.draw(|frame| {
            let rows = [
                format!("Source case: {}", form.source),
                format!("New output: {}", form.output),
                format!(
                    "Storage: {}",
                    if form.linked {
                        "linked (source must remain available)"
                    } else {
                        "bundle (independent copies)"
                    }
                ),
                format!("Allow missing checksums: {}", form.allow_unverified),
                "Verify source".into(),
                "Rebuild report".into(),
            ];
            let mut lines = vec![
                Line::from("Up/Down select; Enter edit/run; Space toggles; Esc exits."),
                Line::from("Source evidence remains unchanged. Keep it stable during review."),
                Line::from(""),
            ];
            for (index, row) in rows.iter().enumerate() {
                lines.push(Line::from(format!(
                    "{} {}{}",
                    if index == form.selected { ">" } else { " " },
                    row,
                    if index == form.selected && form.editing {
                        " [editing]"
                    } else {
                        ""
                    }
                )));
            }
            lines.push(Line::from(""));
            lines.extend(message.lines().map(|line| Line::from(line.to_owned())));
            frame.render_widget(
                Paragraph::new(lines).block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title(" OPSFORGE / SAVED CASE "),
                ),
                frame.area(),
            );
        })?;
        if !event::poll(std::time::Duration::from_millis(100))? {
            continue;
        }
        let Event::Key(key) = event::read()? else {
            continue;
        };
        if key.kind != KeyEventKind::Press {
            continue;
        }
        if pending.0.is_some() {
            message =
                "Review is still running. Waiting for safe completion; no collection is running."
                    .into();
            continue;
        }
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            return Ok(());
        }
        if form.editing {
            form.edit(key.code);
            continue;
        }
        match key.code {
            KeyCode::Esc | KeyCode::Char('q') => return Ok(()),
            KeyCode::Up => form.selected = form.selected.saturating_sub(1),
            KeyCode::Down => form.selected = (form.selected + 1).min(5),
            KeyCode::Enter | KeyCode::Char(' ') => match form.selected {
                0 | 1 => form.editing = true,
                2 => form.linked = !form.linked,
                3 => form.allow_unverified = !form.allow_unverified,
                _ => {
                    let job = form.clone();
                    pending.0 = Some(
                        std::thread::Builder::new()
                            .name("case-review".into())
                            .spawn(move || job.run())?,
                    );
                    message = "Checking saved evidence. Large cases may take time; waiting for safe completion.".into();
                }
            },
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pending_operation_finishes_before_guard_is_dropped() {
        let (send, receive) = std::sync::mpsc::channel();
        let pending = Pending(Some(std::thread::spawn(move || {
            send.send(()).expect("test receiver");
            Ok(String::new())
        })));
        drop(pending);
        assert_eq!(receive.try_recv(), Ok(()));
    }
    #[test]
    fn editing_output_preserves_source_and_accepts_spaces() {
        let mut form = Form {
            source: "original".into(),
            selected: 1,
            editing: true,
            ..Form::default()
        };
        for c in "review folder".chars() {
            form.edit(KeyCode::Char(c));
        }
        form.edit(KeyCode::Enter);
        assert_eq!(form.output, "review folder");
        assert_eq!(form.source, "original");
        assert!(!form.editing);
    }
    #[test]
    fn missing_source_cannot_start_review() {
        assert!(Form::default().run().is_err());
    }
}
