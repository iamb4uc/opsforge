use anyhow::{Context, Result, bail};
use clap::Parser;
use opsforge_investigate::{
    collect,
    config::{CaptureDuration, CheckConfig, LinuxCheck, RunConfig},
    tui,
};
use std::{
    path::PathBuf,
    process::{Command, Stdio},
};

#[derive(Parser)]
#[command(about = "Collect a Linux investigation case with an offline dashboard")]
struct Args {
    #[arg(
        long,
        conflicts_with = "config_stdin",
        help = "Load a JSON case configuration"
    )]
    config: Option<PathBuf>,
    #[arg(long, help = "Print validated settings without sudo or collection")]
    dry_run: bool,
    #[arg(long, help = "Run without the setup TUI")]
    non_interactive: bool,
    #[arg(short, long, help = "Parent directory for the timestamped case")]
    output: Option<PathBuf>,
    #[arg(
        long,
        help = "Live capture duration: positive s, m, h, or d (default: 5m)"
    )]
    duration: Option<CaptureDuration>,
    #[arg(
        long = "import",
        help = "Additional proxy, firewall, VPN, DNS, or other logs"
    )]
    imports: Vec<PathBuf>,
    #[arg(
        long = "check",
        help = "Select a Linux check; target/baseline settings come from --config or the TUI"
    )]
    checks: Vec<LinuxCheck>,
    #[arg(long)]
    no_exfil: bool,
    #[arg(long)]
    no_timeline: bool,
    #[arg(long)]
    no_downloads: bool,
    #[arg(long)]
    no_inventory: bool,
    #[arg(long)]
    no_capture: bool,
    #[arg(long, hide = true)]
    config_stdin: bool,
}

fn main() -> Result<()> {
    let args = Args::parse();
    if args.config_stdin {
        if !is_root()? {
            bail!("--config-stdin requires root");
        }
        let config: RunConfig = serde_json::from_reader(std::io::stdin())?;
        config.validate().map_err(anyhow::Error::msg)?;
        if args.dry_run {
            println!("{}", serde_json::to_string_pretty(&config)?);
            return Ok(());
        }
        return execute(&config, !args.non_interactive);
    }
    let mut config = match args.config {
        Some(path) => serde_json::from_reader(
            std::fs::File::open(&path)
                .with_context(|| format!("opening configuration {}", path.display()))?,
        )
        .context("reading case configuration")?,
        None => RunConfig::default(),
    };
    if let Some(output) = args.output {
        config.output_base = output;
    }
    if let Some(duration) = args.duration {
        config.capture_duration = duration;
    }
    config.imports.extend(args.imports);
    for tool in args.checks {
        if !config.checks.iter().any(|check| check.tool == tool) {
            config.checks.push(CheckConfig::new(tool));
        }
    }
    config.exfil &= !args.no_exfil;
    config.timeline &= !args.no_timeline;
    config.downloads &= !args.no_downloads;
    config.deep_inventory &= !args.no_inventory;
    config.live_capture &= !args.no_capture;
    if args.dry_run || args.non_interactive {
        config.validate().map_err(anyhow::Error::msg)?;
    }
    if args.dry_run {
        println!("{}", serde_json::to_string_pretty(&config)?);
        return Ok(());
    }
    if !args.non_interactive {
        let Some(selected) = tui::configure(config)? else {
            return Ok(());
        };
        config = selected;
    }
    config.validate().map_err(anyhow::Error::msg)?;
    if is_root()? {
        return execute(&config, !args.non_interactive);
    }
    if !command_exists("sudo") {
        bail!("root access is required and sudo is unavailable");
    }
    if !Command::new("sudo")
        .args(["-n", "true"])
        .status()?
        .success()
    {
        eprintln!(
            "Root access is required to collect all available evidence. Requesting sudo now."
        );
        if !Command::new("sudo").arg("-v").status()?.success() {
            bail!("sudo authentication failed; no collection started");
        }
    }
    // /proc pins the executable inode while this process lives; a replaced
    // bootstrap path cannot change what sudo executes.
    let executable = format!("/proc/{}/exe", std::process::id());
    let mut command = Command::new("sudo");
    command
        .arg("--")
        .arg(executable)
        .arg("--config-stdin")
        .stdin(Stdio::piped());
    if args.non_interactive {
        command.arg("--non-interactive");
    }
    let mut child = command.spawn()?;
    serde_json::to_writer(
        child.stdin.take().context("sudo input unavailable")?,
        &config,
    )?;
    let status = child.wait()?;
    if !status.success() {
        bail!("elevated collection failed: {status}");
    }
    Ok(())
}

fn execute(config: &RunConfig, interactive: bool) -> Result<()> {
    collect::install_signal_handlers()?;
    let root = if interactive {
        tui::run_progress(config)?
    } else {
        collect::run(config, &|message| println!("{message}"))?
    };
    println!("Case: {}", root.display());
    println!("Dashboard: {}", root.join("dashboard/index.html").display());
    Ok(())
}

fn is_root() -> Result<bool> {
    let output = Command::new("id")
        .arg("-u")
        .output()
        .context("checking effective user")?;
    if !output.status.success() {
        bail!("id -u failed");
    }
    Ok(output.stdout == b"0\n")
}

fn command_exists(program: &str) -> bool {
    std::env::var_os("PATH")
        .is_some_and(|paths| std::env::split_paths(&paths).any(|path| path.join(program).is_file()))
}
