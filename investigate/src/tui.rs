use crate::config::{CheckConfig, LinuxCheck, RunConfig};
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

const ROWS: usize = 10;

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
                8 => configure_checks(&mut terminal, &mut config)?,
                9 => match config.validate() {
                    Ok(()) => return Ok(Some(config)),
                    Err(message) => error = message.to_owned(),
                },
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
        format!(
            "Linux checks           {} selected (Enter to configure)",
            config.checks.len()
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

fn configure_checks(terminal: &mut ratatui::DefaultTerminal, config: &mut RunConfig) -> Result<()> {
    let mut selected = 0;
    loop {
        terminal.draw(|frame| {
            let mut rows = LinuxCheck::ALL
                .into_iter()
                .map(|tool| {
                    let request = config.checks.iter().find(|check| check.tool == tool);
                    let detail = request.map_or("", |check| {
                        if check.validate().is_err() {
                            " (settings required)"
                        } else {
                            ""
                        }
                    });
                    ListItem::new(format!(
                        "{} {}{detail}",
                        mark(request.is_some()),
                        tool.name()
                    ))
                })
                .collect::<Vec<_>>();
            rows.push(ListItem::new("Done / return to case setup"));
            let mut state = ListState::default();
            state.select(Some(selected));
            frame.render_stateful_widget(
                List::new(rows)
                    .block(
                        Block::default()
                            .borders(Borders::ALL)
                            .title(" Linux checks / Space select / Enter settings / Esc return "),
                    )
                    .highlight_style(Style::default().fg(Color::Cyan))
                    .highlight_symbol("› "),
                frame.area(),
                &mut state,
            );
        })?;
        let Event::Key(key) = event::read()? else {
            continue;
        };
        if key.kind != KeyEventKind::Press {
            continue;
        }
        match key.code {
            KeyCode::Up => selected = selected.saturating_sub(1),
            KeyCode::Down => selected = (selected + 1).min(LinuxCheck::ALL.len()),
            KeyCode::Esc => return Ok(()),
            KeyCode::Enter if selected == LinuxCheck::ALL.len() => return Ok(()),
            KeyCode::Char(' ') | KeyCode::Enter if selected < LinuxCheck::ALL.len() => {
                let tool = LinuxCheck::ALL[selected];
                let existing = config.checks.iter().position(|check| check.tool == tool);
                if key.code == KeyCode::Char(' ') {
                    if let Some(index) = existing {
                        config.checks.remove(index);
                    } else {
                        config.checks.push(CheckConfig::new(tool));
                    }
                } else {
                    let request = existing.map_or_else(
                        || CheckConfig::new(tool),
                        |index| config.checks[index].clone(),
                    );
                    if let Some(request) = configure_check(terminal, request)? {
                        if let Some(index) = existing {
                            config.checks[index] = request;
                        } else {
                            config.checks.push(request);
                        }
                    }
                }
            }
            _ => (),
        }
    }
}

fn configure_check(
    terminal: &mut ratatui::DefaultTerminal,
    mut config: CheckConfig,
) -> Result<Option<CheckConfig>> {
    let mut selected = 0;
    let mut editing: Option<String> = None;
    let mut error = String::new();
    loop {
        terminal.draw(|frame| {
            let area = Layout::default().constraints([Constraint::Min(6), Constraint::Length(4)]).split(frame.area());
            let rows = [
                format!("{}: {}", config.tool.input_label().unwrap_or("Input (not used)"), config.input.as_ref().map_or(String::new(), |path|path.display().to_string())),
                format!("Existing baseline: {}", config.baseline.as_ref().map_or(String::new(), |path|path.display().to_string())),
                format!("{} Create new baseline inside this case", mark(config.create_baseline)),
                "Save and select check".into(),
            ];
            let mut state = ListState::default(); state.select(Some(selected));
            frame.render_stateful_widget(List::new(rows).block(Block::default().borders(Borders::ALL).title(config.tool.name())).highlight_style(Style::default().fg(Color::Cyan)).highlight_symbol("› "),area[0],&mut state);
            let text = editing.as_ref().map_or_else(|| "Enter edit/save; Esc cancel. TLS/network targets cause active probes. Baselines are created only inside this case.".into(), |buffer|format!("Edit: {buffer}\nEnter confirms; empty clears the path."));
            frame.render_widget(Paragraph::new(format!("{text}\n{error}")),area[1]);
        })?;
        let Event::Key(key) = event::read()? else {
            continue;
        };
        if key.kind != KeyEventKind::Press {
            continue;
        }
        if let Some(buffer) = &mut editing {
            match key.code {
                KeyCode::Esc => editing = None,
                KeyCode::Backspace => {
                    buffer.pop();
                }
                KeyCode::Char(character) if !character.is_control() => buffer.push(character),
                KeyCode::Enter => {
                    let path = if buffer.trim().is_empty() {
                        None
                    } else {
                        Some(PathBuf::from(buffer.trim()))
                    };
                    if selected == 0 {
                        config.input = path;
                    } else {
                        config.baseline = path;
                        config.create_baseline = false;
                    }
                    editing = None;
                }
                _ => (),
            }
            continue;
        }
        match key.code {
            KeyCode::Esc => return Ok(None),
            KeyCode::Up => selected = selected.saturating_sub(1),
            KeyCode::Down => selected = (selected + 1).min(3),
            KeyCode::Enter | KeyCode::Char(' ') => match selected {
                0 if config.tool.input_label().is_some() => {
                    editing = Some(
                        config
                            .input
                            .as_ref()
                            .map_or(String::new(), |path| path.display().to_string()),
                    )
                }
                1 if config.tool.needs_baseline() || config.tool == LinuxCheck::NetworkPath => {
                    editing = Some(
                        config
                            .baseline
                            .as_ref()
                            .map_or(String::new(), |path| path.display().to_string()),
                    )
                }
                2 if config.tool.needs_baseline() => {
                    config.create_baseline = !config.create_baseline;
                    if config.create_baseline {
                        config.baseline = None;
                    }
                }
                3 => match config.validate() {
                    Ok(()) => return Ok(Some(config)),
                    Err(message) => error = message.to_owned(),
                },
                _ => error = "this setting does not apply to the selected check".into(),
            },
            _ => (),
        }
    }
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
