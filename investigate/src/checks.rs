use crate::{
    case::{Case, Coverage, CoverageState, Event, EvidenceLevel},
    config::{CheckConfig, LinuxCheck},
    runtime::{self, OwnedChild},
};
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, DirBuilder, File, OpenOptions},
    io::Write,
    os::unix::fs::{DirBuilderExt, MetadataExt},
    path::{Path, PathBuf},
    process::{Command, Stdio},
};
use walkdir::WalkDir;

macro_rules! asset {
    ($path:literal) => {
        ($path, include_str!(concat!("../../", $path)))
    };
}

const LIBRARIES: &[(&str, &str)] = &[
    asset!("lib/common.sh"),
    asset!("lib/logging.sh"),
    asset!("lib/output.sh"),
    asset!("lib/archive.sh"),
    asset!("lib/checks.sh"),
];
const SCRIPTS: &[(LinuxCheck, &str, &str)] = &[
    (
        LinuxCheck::Triage,
        "scripts/linux/endpoint/linux-triage-collector.sh",
        include_str!("../../scripts/linux/endpoint/linux-triage-collector.sh"),
    ),
    (
        LinuxCheck::Persistence,
        "scripts/linux/persistence/linux-persistence-hunter.sh",
        include_str!("../../scripts/linux/persistence/linux-persistence-hunter.sh"),
    ),
    (
        LinuxCheck::DeletedBinaries,
        "scripts/linux/forensic/deleted-binary-detector.sh",
        include_str!("../../scripts/linux/forensic/deleted-binary-detector.sh"),
    ),
    (
        LinuxCheck::ProcessTree,
        "scripts/linux/endpoint/process-tree-anomaly.sh",
        include_str!("../../scripts/linux/endpoint/process-tree-anomaly.sh"),
    ),
    (
        LinuxCheck::Suid,
        "scripts/linux/hardening/suid-drift-monitor.sh",
        include_str!("../../scripts/linux/hardening/suid-drift-monitor.sh"),
    ),
    (
        LinuxCheck::PrivilegeSurface,
        "scripts/linux/hardening/linux-privilege-surface-audit.sh",
        include_str!("../../scripts/linux/hardening/linux-privilege-surface-audit.sh"),
    ),
    (
        LinuxCheck::Ssh,
        "scripts/linux/hardening/ssh-hardening-audit.sh",
        include_str!("../../scripts/linux/hardening/ssh-hardening-audit.sh"),
    ),
    (
        LinuxCheck::ConfigDrift,
        "scripts/linux/hardening/config-drift-monitor.sh",
        include_str!("../../scripts/linux/hardening/config-drift-monitor.sh"),
    ),
    (
        LinuxCheck::NetworkPath,
        "scripts/linux/network/network-path-drift.sh",
        include_str!("../../scripts/linux/network/network-path-drift.sh"),
    ),
    (
        LinuxCheck::DiskPressure,
        "scripts/linux/noc/disk-pressure-rca.sh",
        include_str!("../../scripts/linux/noc/disk-pressure-rca.sh"),
    ),
    (
        LinuxCheck::Tls,
        "scripts/linux/network/tls-inventory-scanner.sh",
        include_str!("../../scripts/linux/network/tls-inventory-scanner.sh"),
    ),
    (
        LinuxCheck::Firewall,
        "scripts/linux/network/firewall-rule-analyzer.sh",
        include_str!("../../scripts/linux/network/firewall-rule-analyzer.sh"),
    ),
    (
        LinuxCheck::LogSilence,
        "scripts/linux/siem/log-source-silence-detector.sh",
        include_str!("../../scripts/linux/siem/log-source-silence-detector.sh"),
    ),
    (
        LinuxCheck::Timeline,
        "scripts/linux/forensic/timeline-builder.sh",
        include_str!("../../scripts/linux/forensic/timeline-builder.sh"),
    ),
    (
        LinuxCheck::WebTriage,
        "scripts/linux/forensic/web-compromise-triage.sh",
        include_str!("../../scripts/linux/forensic/web-compromise-triage.sh"),
    ),
];

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct Finding {
    pub id: String,
    pub title: String,
    pub severity: String,
    pub host: String,
    pub category: String,
    pub evidence: String,
    pub recommendation: String,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct CheckResult {
    pub tool: String,
    pub state: CoverageState,
    pub started_at: String,
    pub finished_at: String,
    pub exit_code: Option<i32>,
    pub detail: String,
    pub evidence: String,
    pub findings: Vec<Finding>,
}

struct StagedTools(PathBuf);

impl Drop for StagedTools {
    fn drop(&mut self) {
        if let Err(error) = fs::remove_dir_all(&self.0)
            && error.kind() != std::io::ErrorKind::NotFound
        {
            eprintln!(
                "could not remove staged checks at {}: {error}",
                self.0.display()
            );
        }
    }
}

fn stage(root: &Path) -> Result<StagedTools> {
    let path = root.join(".check-tools");
    DirBuilder::new().mode(0o700).create(&path)?;
    let stage = StagedTools(path);
    for (name, contents) in LIBRARIES
        .iter()
        .copied()
        .chain(SCRIPTS.iter().map(|(_, path, contents)| (*path, *contents)))
    {
        let file = stage.0.join(name);
        fs::create_dir_all(file.parent().context("asset parent")?)?;
        let mut output = OpenOptions::new().create_new(true).write(true).open(file)?;
        output.write_all(contents.as_bytes())?;
    }
    Ok(stage)
}

pub(crate) fn collect(
    case: &mut Case,
    selected: &[CheckConfig],
    progress: &impl Fn(&str),
) -> Result<()> {
    let mut records = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(case.root.join("normalized/checks.jsonl"))?;
    let tools = if selected.is_empty() {
        None
    } else {
        Some(stage(&case.root)?)
    };
    if tools.is_some() {
        let assets = LIBRARIES.iter().copied().chain(SCRIPTS.iter().map(|(_, path, contents)| (*path, *contents))).map(|(path, contents)|serde_json::json!({"path":path,"sha256":format!("{:x}",Sha256::digest(contents.as_bytes())),"bytes":contents.len()})).collect::<Vec<_>>();
        fs::write(
            case.root.join("raw/check-assets.json"),
            serde_json::to_vec_pretty(&assets)?,
        )?;
        case.record_existing(
            "embedded operational check assets; content hashes",
            "check-assets.json",
        )?;
    }
    for tool in LinuxCheck::ALL {
        runtime::check_cancelled()?;
        let name = tool.name();
        let Some(config) = selected.iter().find(|config| config.tool == tool) else {
            case.coverage(&Coverage {
                source: format!("check-{name}"),
                state: CoverageState::Skipped,
                detail: "operator did not select this operational check".into(),
            })?;
            continue;
        };
        progress(&format!("Running Linux check: {name}"));
        let started_at = jiff::Timestamp::now().to_string();
        let evidence = format!("raw/checks/{name}/command.json");
        let result = run_one(case, config, &tools.as_ref().context("staged checks")?.0);
        let (state, exit_code, detail, findings) = match result {
            Ok(result) => result,
            Err(error) => {
                let exit_code = fs::read(case.root.join(&evidence))
                    .ok()
                    .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
                    .and_then(|audit| audit.get("exit_code").and_then(serde_json::Value::as_i64))
                    .and_then(|code| i32::try_from(code).ok());
                (
                    CoverageState::from_error(&error),
                    exit_code,
                    format!("{error:#}"),
                    Vec::new(),
                )
            }
        };
        let result = CheckResult {
            tool: name.into(),
            state,
            started_at,
            finished_at: jiff::Timestamp::now().to_string(),
            exit_code,
            detail,
            evidence,
            findings,
        };
        serde_json::to_writer(&mut records, &result)?;
        records.write_all(b"\n")?;
        records.flush()?;
        case.coverage(&Coverage {
            source: format!("check-{name}"),
            state,
            detail: result.detail.clone(),
        })?;
        case.event(&Event {
            timestamp: Some(result.finished_at.clone()),
            source: format!("check-{name}"),
            kind: "operational-check".into(),
            application: Some("opsforge".into()),
            user: None,
            destination: None,
            detail: format!(
                "{}; {} finding(s); these are check results, not proof of compromise",
                result.detail,
                result.findings.len()
            ),
            evidence: result.evidence.clone(),
            level: EvidenceLevel::Observed,
            transfer: None,
            evidence_line: None,
        })?;
        runtime::check_cancelled()?;
    }
    if let Some(tools) = tools {
        fs::remove_dir_all(&tools.0).context("removing owned staged checks")?;
        case.coverage(&Coverage {
            source: "check-tools-cleanup".into(),
            state: CoverageState::Collected,
            detail: "removed this run's staged scripts and tool state; retained case evidence"
                .into(),
        })?;
    }
    Ok(())
}

fn run_one(
    case: &mut Case,
    config: &CheckConfig,
    tools: &Path,
) -> Result<(CoverageState, Option<i32>, String, Vec<Finding>)> {
    let name = config.tool.name();
    let parent = case.root.join("raw/checks").join(name);
    fs::create_dir_all(&parent)?;
    let script = SCRIPTS
        .iter()
        .find(|(tool, _, _)| *tool == config.tool)
        .context("embedded check")?;
    let mut args = vec![
        tools.join(script.1).into_os_string(),
        "--output".into(),
        parent.as_os_str().to_owned(),
        "--json".into(),
        "--markdown".into(),
        "--verbose".into(),
    ];
    if let Some(input) = &config.input {
        let input = case.copy_evidence(input, &format!("check-{name}-input.conf"))?;
        args.push(
            if config.tool == LinuxCheck::LogSilence {
                "--config"
            } else {
                "--targets"
            }
            .into(),
        );
        args.push(input.into_os_string());
    }
    if config.tool.needs_baseline() {
        args.push(
            if config.create_baseline {
                "--baseline"
            } else {
                "--check"
            }
            .into(),
        );
        args.push(
            if config.tool == LinuxCheck::Suid {
                "--baseline-file"
            } else {
                "--baseline-dir"
            }
            .into(),
        );
        args.push(if config.create_baseline {
            parent.join("baseline").into_os_string()
        } else {
            preserve_baseline(
                case,
                config.baseline.as_ref().context("existing baseline")?,
                name,
            )?
            .into_os_string()
        });
    } else if let Some(baseline) = &config.baseline {
        args.push("--baseline".into());
        args.push(preserve_baseline(case, baseline, name)?.into_os_string());
    }
    let audit = parent.join("command.json");
    let started = jiff::Timestamp::now().to_string();
    let uid = fs::metadata(&case.root)?.uid().to_string();
    let passwd = fs::read_to_string("/etc/passwd")?;
    let home = passwd
        .lines()
        .find_map(|line| {
            let fields = line.split(':').collect::<Vec<_>>();
            (fields.get(2) == Some(&uid.as_str()))
                .then(|| fields.get(5).copied())
                .flatten()
        })
        .filter(|home| Path::new(home).is_absolute())
        .context("collection account home is missing from /etc/passwd")?;
    let mut command = Command::new("bash");
    command
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .env("LC_ALL", "C")
        .env("HOME", home)
        .env("OPSFORGE_SKIP_ARCHIVE", "1")
        .env("OPSFORGE_FALLBACK_OUTPUT", &parent)
        .args(&args)
        .current_dir(tools)
        .stdin(Stdio::null())
        .stdout(File::create(parent.join("stdout.log"))?)
        .stderr(File::create(parent.join("stderr.log"))?);
    let mut record = serde_json::json!({"program":"bash", "args":args.iter().map(|arg|arg.to_string_lossy()).collect::<Vec<_>>(), "started_at":started, "script_sha256":format!("{:x}",Sha256::digest(script.2.as_bytes())), "environment":"cleared; fixed system PATH; LC_ALL=C; no archive", "home":home, "status":"started"});
    fs::write(&audit, serde_json::to_vec_pretty(&record)?)?;
    let status = OwnedChild::spawn(&mut command)?.wait()?;
    record["status"] = serde_json::json!(if status.success() { "exited" } else { "failed" });
    record["exit_code"] = serde_json::json!(status.code());
    record["finished_at"] = serde_json::json!(jiff::Timestamp::now().to_string());
    fs::write(&audit, serde_json::to_vec_pretty(&record)?)?;
    for entry in WalkDir::new(&parent).follow_links(false) {
        let entry = entry?;
        if entry.file_type().is_file() {
            let path = entry
                .path()
                .strip_prefix(case.root.join("raw"))?
                .to_str()
                .context("check output path")?
                .to_owned();
            case.record_existing(&format!("opsforge {name}; generated check output"), &path)?;
        }
    }
    let mut outputs = fs::read_dir(&parent)?
        .filter_map(|entry| entry.ok())
        .filter(|entry| {
            entry.file_type().is_ok_and(|kind| kind.is_dir()) && entry.file_name() != "baseline"
        })
        .collect::<Vec<_>>();
    if outputs.len() != 1 {
        bail!(
            "check produced {} output directories; exit {:?}; inspect stdout/stderr",
            outputs.len(),
            status.code()
        );
    }
    let output = outputs.remove(0).path();
    for required in [
        "raw",
        "normalized",
        "findings.json",
        "summary.txt",
        "report.md",
    ] {
        if !output.join(required).exists() {
            bail!("check output missing {required}; exit {:?}", status.code());
        }
    }
    let mut findings: Vec<Finding> =
        serde_json::from_reader(File::open(output.join("findings.json"))?)?;
    let finding_path = output
        .join("findings.json")
        .strip_prefix(&case.root)?
        .to_str()
        .context("finding path")?
        .to_owned();
    for finding in &mut findings {
        if !["critical", "high", "medium", "low", "info"].contains(&finding.severity.as_str()) {
            bail!("invalid check finding severity");
        }
        finding.evidence = finding_path.clone();
    }
    let collection = output.join("normalized/collection-status.tsv");
    let failed_commands = if collection.exists() {
        fs::read_to_string(collection)?
            .lines()
            .skip(1)
            .filter(|line| {
                line.split('\t')
                    .nth(3)
                    .is_some_and(|state| state != "collected")
            })
            .count()
    } else {
        0
    };
    let state = if status.success() && failed_commands == 0 {
        CoverageState::Collected
    } else {
        CoverageState::Failed
    };
    Ok((
        state,
        status.code(),
        format!(
            "exit {:?}; {failed_commands} failed or unavailable commands; original reports retained",
            status.code()
        ),
        findings,
    ))
}

fn preserve_baseline(case: &mut Case, input: &Path, name: &str) -> Result<PathBuf> {
    let destination = format!("check-{name}-baseline");
    if input.is_file() {
        return case.copy_evidence(input, &destination);
    }
    if !input.is_dir() {
        bail!("baseline is not a file or directory: {}", input.display());
    }
    let root = case.root.join("raw").join(&destination);
    fs::create_dir(&root)?;
    for entry in WalkDir::new(input).follow_links(false) {
        runtime::check_cancelled()?;
        let entry = entry?;
        if entry.file_type().is_symlink() {
            bail!("baseline contains a symlink: {}", entry.path().display());
        }
        if !entry.file_type().is_file() {
            continue;
        }
        let relative = entry
            .path()
            .strip_prefix(input)?
            .to_str()
            .context("baseline path is not UTF-8")?;
        let name = format!("{destination}/{relative}");
        fs::create_dir_all(root.join(relative).parent().context("baseline parent")?)?;
        case.copy_evidence(entry.path(), &name)?;
    }
    Ok(root)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn staged_tools_cover_all_checks_and_ignore_shell_startup_code() {
        let root =
            std::env::temp_dir().join(format!("opsforge-staged-checks-{}", std::process::id()));
        fs::create_dir(&root).expect("fixture");
        let marker = root.join("startup-ran");
        let startup = root.join("startup.sh");
        fs::write(&startup, format!("touch '{}'\n", marker.display())).expect("startup fixture");
        let staged = stage(&root).expect("stage");
        assert_eq!(SCRIPTS.len(), LinuxCheck::ALL.len());
        for (tool, path, _) in SCRIPTS {
            assert!(LinuxCheck::ALL.contains(tool));
            let status = Command::new("bash")
                .env("BASH_ENV", &startup)
                .env_clear()
                .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
                .arg(staged.0.join(path))
                .arg("--help")
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .expect("help");
            assert!(status.success(), "{} help", tool.name());
        }
        assert!(!marker.exists());
        drop(staged);
        assert!(!root.join(".check-tools").exists());
        fs::remove_dir_all(root).expect("cleanup");
    }
}
