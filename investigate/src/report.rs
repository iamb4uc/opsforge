use crate::case::{Coverage, CoverageState, Event, EvidenceFile};
use anyhow::Result;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{self, File},
    io::{BufRead, BufReader, BufWriter, Read, Write},
    path::Path,
};
use walkdir::WalkDir;

pub fn generate(root: &Path) -> Result<()> {
    let coverage = read_lines::<Coverage>(&root.join("normalized/coverage.jsonl"))?;
    let manifest = read_lines::<EvidenceFile>(&root.join("manifest.jsonl"))?;
    let failures = coverage
        .iter()
        .filter(|row| matches!(row.state, CoverageState::Failed))
        .count();
    let mut data = BufWriter::new(File::create(root.join("dashboard/events.js"))?);
    writeln!(data, "window.caseEvents = [")?;
    let (mut count, mut uploads, mut downloads, mut leads, mut completed) =
        (0_u64, 0_u64, 0_u64, 0_u64, 0_u64);
    let mut applications = BTreeMap::<String, u64>::new();
    let mut inventory = BTreeMap::<String, u64>::new();
    let mut activity = BTreeMap::<String, u64>::new();
    for line in BufReader::new(File::open(root.join("normalized/events.jsonl"))?).lines() {
        let event: Event = serde_json::from_str(&line?)?;
        if count > 0 {
            writeln!(data, ",")?;
        }
        write!(data, "{}", script_json(&event)?)?;
        count += 1;
        if event.kind == "application-inventory" {
            *inventory.entry(event.source.clone()).or_default() += 1;
        } else if let Some(application) = &event.application {
            *activity.entry(application.clone()).or_default() += 1;
        }
        if event.kind == "network-lead" {
            leads += 1;
        }
        if let Some(transfer) = &event.transfer {
            if transfer.direction == "upload" {
                uploads += 1;
                if transfer.status == "completed" {
                    completed += 1;
                }
            }
            if transfer.direction == "download" {
                downloads += 1;
            }
            *applications
                .entry(
                    event
                        .application
                        .clone()
                        .unwrap_or_else(|| "Unattributed".into()),
                )
                .or_default() += 1;
        } else if event.kind == "download" {
            downloads += 1;
        }
    }
    writeln!(data, "\n];")?;
    data.flush()?;
    let info = root.join("case-info.json");
    let info: serde_json::Value = if info.exists() {
        serde_json::from_reader(File::open(info)?)?
    } else {
        serde_json::json!({})
    };
    fs::write(
        root.join("dashboard/case.js"),
        format!(
            "window.caseData = {};\n",
            script_json(&serde_json::json!({
            "name": info.get("case_id").cloned().unwrap_or_else(|| serde_json::json!(root.file_name().unwrap_or_default().to_string_lossy())), "info": info, "coverage": coverage, "manifest": manifest,
                    "counts": {"events": count, "uploads": uploads, "completed": completed, "downloads": downloads, "leads": leads, "failed": failures}
                }))?
        ),
    )?;
    fs::write(
        root.join("dashboard/style.css"),
        include_str!("dashboard.css"),
    )?;
    fs::write(root.join("dashboard/app.js"), include_str!("dashboard.js"))?;
    fs::write(root.join("findings.json"), b"[]\n")?;
    fs::write(root.join("normalized/findings.json"), b"[]\n")?;
    fs::write(
        root.join("summary.txt"),
        format!(
            "Output: {}\nFindings: 0\nEvents: {count}\nUpload records: {uploads}\nCompleted upload records: {completed}\nNetwork leads: {leads}\nDownloads: {downloads}\nFailed sources: {failures}\n",
            root.display()
        ),
    )?;
    fs::write(
        root.join("report.md"),
        format!(
            "# Linux investigator case\n\nCase: `{}`\n\n- Events: {count}\n- Upload records: {uploads}\n- Completed upload records: {completed}\n- Download records: {downloads}\n- Network leads: {leads}\n- Failed sources: {failures}\n\nTransfer records retain their source perspective. An upload to a local server is inbound to that server, not proof of device exfiltration. HTTP success means a request was accepted, not that a named file was uploaded. Unknown fields remain unknown.\n\nOpen `dashboard/index.html`. Every normalized event is searchable there; JSONL and raw files remain the evidence of record.\n",
            root.display()
        ),
    )?;
    let graphs = bar_graph("Transfer records by application", &applications);
    let application_graphs = format!(
        "{}{}",
        bar_graph("Package records by manager", &inventory),
        bar_graph("Activity records by application", &activity)
    );
    for (name, title, note) in [
        (
            "index",
            "Case overview",
            "Counts describe records, not unique files or confirmed exfiltration.",
        ),
        (
            "exfil",
            "Uploads",
            "File transfers and upload requests. Server records describe inbound uploads; client records may describe outbound transfers. Accepted HTTP requests do not establish the original file name or payload.",
        ),
        (
            "timeline",
            "Device timeline",
            "All retained events, sorted by known time. Packet summaries are hidden initially; enable them below. Unknown or local times remain labelled and sort after known UTC times.",
        ),
        (
            "downloads",
            "Downloads",
            "Browser metadata, file transfers and HTTP download requests. A successful GET is not necessarily a downloaded file. Inspect outcome and byte basis.",
        ),
        (
            "network",
            "Network activity",
            "Connections, listeners, browser visits, network leads and packet summaries. These records alone do not prove an upload.",
        ),
        (
            "applications",
            "Applications",
            "Current package inventory and retained application activity. Package records describe collection-time state, not installation time or proof of traffic. Activity records retain their own source perspective and identity limits.",
        ),
        (
            "collection",
            "Source coverage",
            "Unsupported or absent history is not evidence that activity did not occur.",
        ),
        (
            "evidence",
            "Evidence files",
            "Original source mappings, acquisition times, sizes and SHA-256 hashes. Download a retained raw file to inspect its referenced record.",
        ),
    ] {
        page(
            root,
            name,
            title,
            note,
            match name {
                "index" => &graphs,
                "applications" => &application_graphs,
                _ => "",
            },
        )?;
    }
    Ok(())
}

fn bar_graph(title: &str, counts: &BTreeMap<String, u64>) -> String {
    let mut html = format!("<section class=\"panel\"><h2>{}</h2>", escape(title));
    let max = counts.values().copied().max().unwrap_or(1).max(1);
    for (name, value) in counts {
        html.push_str(&format!("<label class=\"bar\"><span>{}</span><meter min=\"0\" max=\"{max}\" value=\"{value}\">{value}</meter><b>{value}</b></label>", escape(name)));
    }
    if counts.is_empty() {
        html.push_str("<p>No records in this category. Review Coverage for missing or unsupported sources.</p>");
    }
    html.push_str("</section>");
    html
}

pub fn write_checksums(root: &Path) -> Result<()> {
    let mut output = File::create(root.join("checksums.sha256"))?;
    for entry in WalkDir::new(root).sort_by_file_name() {
        let entry = entry?;
        if !entry.file_type().is_file() || entry.file_name() == "checksums.sha256" {
            continue;
        }
        let mut file = File::open(entry.path())?;
        let mut hash = Sha256::new();
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            let bytes = file.read(&mut buffer)?;
            if bytes == 0 {
                break;
            }
            hash.update(&buffer[..bytes]);
        }
        writeln!(
            output,
            "{:x}  {}",
            hash.finalize(),
            entry.path().strip_prefix(root)?.display()
        )?;
    }
    Ok(())
}

fn read_lines<T: serde::de::DeserializeOwned>(path: &Path) -> Result<Vec<T>> {
    BufReader::new(File::open(path)?)
        .lines()
        .map(|line| Ok(serde_json::from_str(&line?)?))
        .collect()
}

fn script_json(value: &impl serde::Serialize) -> Result<String> {
    Ok(serde_json::to_string(value)?
        .replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .replace('&', "\\u0026")
        .replace('\u{2028}', "\\u2028")
        .replace('\u{2029}', "\\u2029"))
}

fn page(root: &Path, name: &str, title: &str, note: &str, content: &str) -> Result<()> {
    let tabs = [
        ("index", "Overview"),
        ("exfil", "Uploads"),
        ("timeline", "Timeline"),
        ("downloads", "Downloads"),
        ("network", "Network"),
        ("applications", "Applications"),
        ("collection", "Coverage"),
        ("evidence", "Evidence"),
    ];
    let nav = tabs
        .iter()
        .map(|(target, label)| {
            format!(
                "<a href=\"{target}.html\"{}>{label}</a>",
                if *target == name {
                    " aria-current=\"page\""
                } else {
                    ""
                }
            )
        })
        .collect::<String>();
    let html = format!(
        r##"<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'none'; object-src 'none'; base-uri 'none'"><title>{title} | opsforge</title><link rel="stylesheet" href="style.css"><script defer src="case.js"></script><script defer src="events.js"></script><script defer src="app.js"></script></head><body data-view="{name}"><a class="skip" href="#main">Skip to records</a><header><b>opsforge</b><span>Linux investigator</span><a href="../report.md">Case report</a></header><div class="case-strip"><strong id="case-name">Case</strong><span id="case-info"></span></div><nav aria-label="Case sections">{nav}</nav><main id="main"><h1>{title}</h1><p class="note">{note}</p><section id="totals" aria-label="Case counts"></section>{content}<section class="panel" id="records"><h2 id="records-title">Records</h2><form id="filters"><label>Search<input id="search" type="search" placeholder="File, URL, user, application or raw text"></label><label>Application<select id="application"><option value="">All applications</option></select></label><label>Source<select id="source"><option value="">All sources</option></select></label><label>Outcome<select id="status"><option value="">All outcomes</option></select></label><label>From (UTC)<input id="from" type="datetime-local"></label><label>Until (UTC)<input id="until" type="datetime-local"></label><label>Sort<select id="sort"><option value="newest">Newest time</option><option value="oldest">Oldest time</option><option value="collection">Collection order</option></select></label><label class="check"><input id="packets" type="checkbox">Include packet summaries</label><button type="reset">Reset filters</button></form><p id="result-count" role="status" aria-live="polite"></p><div class="scroll" tabindex="0" aria-label="Records table"><table id="table"><thead></thead><tbody></tbody></table></div><div class="pagination"><button id="previous" type="button">Previous</button><span id="page-position"></span><button id="next" type="button">Next</button><label>Rows<select id="page-size"><option>50</option><option selected>100</option><option>250</option></select></label></div></section><noscript>Enable JavaScript to search the complete case. Raw and normalized evidence remains available below.</noscript></main><footer><a href="../normalized/events.jsonl" download>All events (JSONL)</a><a href="../normalized/coverage.jsonl" download>Coverage (JSONL)</a><a href="../manifest.jsonl" download>Raw manifest</a><a href="../checksums.sha256" download>Case checksums</a><span>Offline report. Keep the entire case directory together.</span></footer></body></html>"##
    );
    fs::write(root.join("dashboard").join(format!("{name}.html")), html)?;
    Ok(())
}

fn escape(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

#[cfg(test)]
mod tests {
    use super::{escape, script_json};
    #[test]
    fn escapes_collected_text() {
        assert_eq!(escape("<script x='&'>"), "&lt;script x=&#39;&amp;&#39;&gt;");
        let encoded = script_json(&"</script><img onerror=alert(1)>\u{2028}").expect("json");
        assert!(!encoded.contains('<'));
        assert!(encoded.contains("\\u2028"));
        assert_eq!(
            serde_json::from_str::<String>(&encoded).expect("decode"),
            "</script><img onerror=alert(1)>\u{2028}"
        );
    }
}
