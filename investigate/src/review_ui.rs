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

#[derive(Default)]
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

/// Configure and run saved-case operations without acquisition or elevation.
pub fn run() -> Result<()> {
    if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
        bail!("review needs a terminal; use verify or rebuild for automation");
    }
    let mut terminal = ratatui::init();
    let _restore = Restore;
    let mut form = Form::default();
    let mut message = String::new();
    loop {
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
        let Event::Key(key) = event::read()? else {
            continue;
        };
        if key.kind != KeyEventKind::Press {
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
                    terminal.draw(|frame| frame.render_widget(Paragraph::new("Checking saved evidence. Large cases may take time; no collection is running."), frame.area()))?;
                    message = match form.run() {
                        Ok(value) => value,
                        Err(error) => format!("Failed: {error:#}"),
                    };
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
