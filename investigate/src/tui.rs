use crate::config::RunConfig;
use anyhow::{Context, Result};
use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph},
};
use std::{cell::RefCell, io::IsTerminal, path::PathBuf};

const ROWS: usize = 9;

struct TerminalGuard;

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        ratatui::restore();
    }
}

pub fn configure(mut config: RunConfig) -> Result<Option<RunConfig>> {
    if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
        anyhow::bail!("interactive setup needs a terminal; use --non-interactive for automation");
    }
    let mut terminal = ratatui::init();
    let _guard = TerminalGuard;
    let mut selected = 0;
    let mut input: Option<(usize, String)> = None;
    let mut error = String::new();

    loop {
        terminal.draw(|frame| draw(frame, &config, selected, input.as_ref(), &error))?;
        let Event::Key(key) = event::read().context("reading terminal input")? else {
            continue;
        };
        if key.kind != KeyEventKind::Press {
            continue;
        }
        if let Some((field, buffer)) = &mut input {
            match key.code {
                KeyCode::Esc => input = None,
                KeyCode::Backspace => {
                    buffer.pop();
                }
                KeyCode::Enter => {
                    let value = buffer.trim();
                    match *field {
                        0 if !value.is_empty() => config.output_base = PathBuf::from(value),
                        6 => match value.parse() {
                            Ok(duration) => config.capture_duration = duration,
                            Err(message) => {
                                error = message.to_owned();
                                continue;
                            }
                        },
                        7 if !value.is_empty() => config.imports.push(PathBuf::from(value)),
                        0 | 7 => {
                            error = "enter a path".to_owned();
                            continue;
                        }
                        _ => {}
                    }
                    error.clear();
                    input = None;
                }
                KeyCode::Char(character) if !character.is_control() => buffer.push(character),
                _ => {}
            }
            continue;
        }
        error.clear();
        match key.code {
            KeyCode::Up => selected = selected.saturating_sub(1),
            KeyCode::Down => selected = (selected + 1).min(ROWS - 1),
            KeyCode::Esc | KeyCode::Char('q') => return Ok(None),
            KeyCode::Enter | KeyCode::Char(' ') => match selected {
                0 => input = Some((0, config.output_base.display().to_string())),
                1 => config.exfil = !config.exfil,
                2 => config.timeline = !config.timeline,
                3 => config.downloads = !config.downloads,
                4 => config.deep_inventory = !config.deep_inventory,
                5 => config.live_capture = !config.live_capture,
                6 => input = Some((6, config.capture_duration.to_string())),
                7 => input = Some((7, String::new())),
                8 => return Ok(Some(config)),
                _ => {}
            },
            _ => {}
        }
    }
}

fn draw(
    frame: &mut Frame<'_>,
    config: &RunConfig,
    selected: usize,
    input: Option<&(usize, String)>,
    error: &str,
) {
    let area = frame.area();
    let outer = Block::default()
        .borders(Borders::ALL)
        .title(" OPSFORGE / LINUX INVESTIGATOR ");
    frame.render_widget(outer, area);
    let inner = area.inner(ratatui::layout::Margin {
        horizontal: 2,
        vertical: 1,
    });
    let sections = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(10),
            Constraint::Length(4),
        ])
        .split(inner);
    frame.render_widget(
        Paragraph::new(
            "Check the case output location and select sources. Gaps remain visible in the report.",
        )
        .style(Style::default().fg(Color::Gray)),
        sections[0],
    );
    let rows = [
        format!("Case output            {}", config.output_base.display()),
        format!("{} Exfiltration evidence", mark(config.exfil)),
        format!("{} Device timeline", mark(config.timeline)),
        format!("{} Browser downloads", mark(config.downloads)),
        format!("{} Deep file inventory", mark(config.deep_inventory)),
        format!("{} Live traffic capture", mark(config.live_capture)),
        format!("Capture duration       {}", config.capture_duration),
        format!(
            "Additional logs        {} path(s) selected",
            config.imports.len()
        ),
        "Review and start collection".to_owned(),
    ];
    let items = rows.into_iter().map(ListItem::new).collect::<Vec<_>>();
    let mut state = ListState::default();
    state.select(Some(selected));
    let list = List::new(items)
        .highlight_style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("› ");
    frame.render_stateful_widget(list, sections[1], &mut state);
    let mut footer = vec![if let Some((_, buffer)) = input {
        Line::from(vec![
            Span::styled("Edit: ", Style::default().fg(Color::Cyan)),
            Span::raw(buffer),
        ])
    } else {
        Line::from("↑↓ move  ·  Space toggle  ·  Enter edit/start  ·  Esc quit")
    }];
    if !error.is_empty() {
        footer.push(Line::from(Span::styled(
            error,
            Style::default().fg(Color::Red),
        )));
    }
    frame.render_widget(
        Paragraph::new(footer).block(Block::default().borders(Borders::TOP)),
        sections[2],
    );
}

fn mark(enabled: bool) -> &'static str {
    if enabled { "[x]" } else { "[ ]" }
}

pub fn run_progress(config: &RunConfig) -> Result<PathBuf> {
    let terminal = RefCell::new(ratatui::init());
    let _guard = TerminalGuard;
    let updates = RefCell::new(Vec::<String>::new());
    let finished = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let input_finished = std::sync::Arc::clone(&finished);
    let input = std::thread::spawn(move || {
        while !input_finished.load(std::sync::atomic::Ordering::Relaxed) {
            match event::poll(std::time::Duration::from_millis(50)) {
                Ok(true) => match event::read() {
                    Ok(Event::Key(key))
                        if matches!(key.code, KeyCode::Char('c' | 'C'))
                            && key.modifiers.contains(KeyModifiers::CONTROL) =>
                    {
                        crate::runtime::cancel()
                    }
                    Err(_) => break,
                    _ => (),
                },
                Ok(false) => (),
                Err(_) => break,
            }
        }
    });
    let result = crate::collect::run(config, &|message| {
        let mut lines = updates.borrow_mut();
        lines.push(message.to_owned());
        if lines.len() > 16 {
            lines.remove(0);
        }
        let _ = terminal.borrow_mut().draw(|frame| {
            let area = frame.area();
            let block = Block::default()
                .borders(Borders::ALL)
                .title(" OPSFORGE / COLLECTING · Ctrl-C cancel ");
            frame.render_widget(block, area);
            let inner = area.inner(ratatui::layout::Margin {
                horizontal: 2,
                vertical: 1,
            });
            frame.render_widget(Paragraph::new(lines.join("\n")), inner);
        });
    });
    finished.store(true, std::sync::atomic::Ordering::Relaxed);
    let _ = input.join();
    result
}

#[cfg(test)]
mod tests {
    use super::draw;
    use crate::config::RunConfig;
    use ratatui::{Terminal, backend::TestBackend};

    #[test]
    fn invalid_duration_error_stays_visible_while_editing() {
        let mut terminal = Terminal::new(TestBackend::new(100, 30)).expect("terminal");
        let config = RunConfig::default_for("/var/lib/opsforge/cases".into());
        let input = Some((6, "1w".into()));
        let error = "capture duration unit must be s, m, h, or d";
        terminal
            .draw(|frame| draw(frame, &config, 6, input.as_ref(), error))
            .expect("draw");
        let text: String = terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|cell| cell.symbol())
            .collect();
        assert!(text.contains("Edit: 1w"));
        assert!(text.contains(error));
    }
}
