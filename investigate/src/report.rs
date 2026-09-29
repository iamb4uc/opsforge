use crate::case::{Coverage, Event};
use anyhow::Result;
use sha2::{Digest, Sha256};
use std::{
    collections::VecDeque,
    fs::{self, File},
    io::{BufRead, BufReader, Read, Write},
    path::Path,
};
use walkdir::WalkDir;

const LIMIT: usize = 2_000;

pub fn generate(root: &Path) -> Result<()> {
    let events = read_events(&root.join("normalized/events.jsonl"))?;
    let coverage = read_lines::<Coverage>(&root.join("normalized/coverage.jsonl"))?;
    let failures = coverage
        .iter()
        .filter(|row| format!("{:?}", row.state) == "Failed")
        .count();
    let leads = events.leads;
    let downloads = events.downloads;
    let other = events.count.saturating_sub(leads.saturating_add(downloads));
    let graph_max = events.count.max(1);
    fs::write(root.join("findings.json"), b"[]\n")?;
    fs::write(root.join("normalized/findings.json"), b"[]\n")?;
    fs::write(
        root.join("summary.txt"),
        format!(
            "Output: {}\nFindings: 0\nEvents: {}\nNetwork leads: {leads}\nDownloads: {downloads}\nFailed sources: {failures}\n",
            root.display(),
            events.count
        ),
    )?;
    fs::write(
        root.join("report.md"),
        format!(
            "# Linux investigator case\n\nCase: `{}`\n\n- Events: {}\n- Network leads: {leads}\n- Downloads: {downloads}\n- Failed sources: {failures}\n\nNo automated exfiltration conclusion is made from browser visits, journal keywords, or a packet capture alone. Check the raw evidence and source coverage before reaching a conclusion.\n\nOpen `dashboard/index.html` for the offline report. Full records are in `normalized/events.jsonl` and `normalized/coverage.jsonl`.\n",
            root.display(),
            events.count
        ),
    )?;
    fs::write(
        root.join("dashboard/style.css"),
        format!("{STYLE}{GRAPH_STYLE}{TABLE_STYLE}"),
    )?;

    let overview = format!(
        "<section class=\"cards\"><div><strong>{}</strong><span>events</span></div><div><strong>{leads}</strong><span>network leads</span></div><div><strong>{downloads}</strong><span>downloads</span></div><div><strong>{failures}</strong><span>failed sources</span></div></section><section class=\"breakdown\" aria-labelledby=\"shape\"><h2 id=\"shape\">Evidence shape</h2><label>Network leads <span>{leads}</span><meter min=\"0\" max=\"{graph_max}\" value=\"{leads}\">{leads}</meter></label><label>Downloads <span>{downloads}</span><meter min=\"0\" max=\"{graph_max}\" value=\"{downloads}\">{downloads}</meter></label><label>Other events <span>{other}</span><meter min=\"0\" max=\"{graph_max}\" value=\"{other}\">{other}</meter></label></section><p>These counts show available evidence, not complete device history or confirmed exfiltration.</p><p><a href=\"../normalized/events.jsonl\">All normalized events</a> · <a href=\"../manifest.jsonl\">Evidence hashes</a></p>",
        events.count
    );
    page(root, "index", "Case overview", &overview)?;

    let network: Vec<_> = events.network.iter().collect();
    page(
        root,
        "exfil",
        "Exfiltration review",
        &format!(
            "<p>Network and browser activity are leads. A visit or keyword does not prove an upload. Compare these records with packet and imported network logs.</p>{}",
            event_table(&network, events.network_count)
        ),
    )?;
    let mut timeline: Vec<_> = events.timeline.iter().collect();
    timeline.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));
    page(
        root,
        "timeline",
        "Device timeline",
        &format!(
            "<p>Times are recorded in source form where available. Missing times sort first.</p>{}",
            event_table(&timeline, events.count)
        ),
    )?;
    let downloaded: Vec<_> = events.download_rows.iter().collect();
    page(
        root,
        "downloads",
        "Downloads",
        &format!(
            "<p>Browser download records are historical metadata. Inspect the referenced database and file before classifying a download.</p>{}",
            event_table(&downloaded, downloads)
        ),
    )?;
    let mut rows = String::from(
        "<table><thead><tr><th>Source</th><th>Status</th><th>Detail</th></tr></thead><tbody>",
    );
    for row in &coverage {
        rows.push_str(&format!(
            "<tr><td>{}</td><td>{:?}</td><td>{}</td></tr>",
            escape(&row.source),
            row.state,
            escape(&row.detail)
        ));
    }
    rows.push_str(
        "</tbody></table><p><a href=\"../normalized/coverage.jsonl\">Full coverage log</a></p>",
    );
    page(root, "collection", "Collection coverage", &rows)?;
    Ok(())
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
    let mut result = Vec::new();
    for line in BufReader::new(File::open(path)?).lines() {
        result.push(serde_json::from_str(&line?)?);
    }
    Ok(result)
}

#[derive(Default)]
struct EventSamples {
    count: usize,
    leads: usize,
    downloads: usize,
    network_count: usize,
    timeline: VecDeque<Event>,
    network: VecDeque<Event>,
    download_rows: VecDeque<Event>,
}

fn read_events(path: &Path) -> Result<EventSamples> {
    let mut samples = EventSamples::default();
    for line in BufReader::new(File::open(path)?).lines() {
        let event: Event = serde_json::from_str(&line?)?;
        samples.count = samples.count.saturating_add(1);
        if event.kind == "network-lead" {
            samples.leads = samples.leads.saturating_add(1);
        }
        if event.kind == "download" {
            samples.downloads = samples.downloads.saturating_add(1);
            retain(&mut samples.download_rows, event.clone());
        }
        if matches!(
            event.kind.as_str(),
            "network-lead" | "active-connection" | "inbound-listener" | "packet"
        ) || event.source == "browser-history"
        {
            samples.network_count = samples.network_count.saturating_add(1);
            retain(&mut samples.network, event.clone());
        }
        retain(&mut samples.timeline, event);
    }
    Ok(samples)
}

fn retain(rows: &mut VecDeque<Event>, event: Event) {
    if rows.len() == LIMIT {
        rows.pop_front();
    }
    rows.push_back(event);
}

fn event_table(events: &[&Event], total: usize) -> String {
    let mut body = format!(
        "<p>Showing the last {} collected records of {}. The JSONL file contains every record.</p><div class=\"scroll\"><table class=\"evidence-table\"><thead><tr><th>Time</th><th>Source</th><th>Kind</th><th>Application</th><th>Destination or path</th><th>Detail</th><th>Evidence level</th><th>Raw</th></tr></thead><tbody>",
        events.len(),
        total
    );
    for event in events {
        let raw = if event.evidence.starts_with("raw/") && !event.evidence.contains("..") {
            format!("<a href=\"../{}\">source</a>", escape(&event.evidence))
        } else {
            String::new()
        };
        body.push_str(&format!("<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{:?}</td><td>{raw}</td></tr>",
            escape(event.timestamp.as_deref().unwrap_or("unknown")), escape(&event.source), escape(&event.kind), escape(event.application.as_deref().unwrap_or("unattributed")), escape(event.destination.as_deref().unwrap_or("")), escape(&event.detail), event.level));
    }
    body.push_str("</tbody></table></div>");
    body
}

fn page(root: &Path, name: &str, title: &str, content: &str) -> Result<()> {
    let mut file = File::create(root.join("dashboard").join(format!("{name}.html")))?;
    write!(
        file,
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'self'; img-src 'self'; connect-src 'none'\"><title>{} · opsforge</title><link rel=\"stylesheet\" href=\"style.css\"></head><body><header><p class=\"brand\">OPSFORGE / INVESTIGATOR</p><nav aria-label=\"Case sections\"><a href=\"index.html\">Overview</a><a href=\"exfil.html\">Exfiltration</a><a href=\"timeline.html\">Timeline</a><a href=\"downloads.html\">Downloads</a><a href=\"collection.html\">Coverage</a></nav></header><main><p class=\"eyebrow\">LINUX CASE REPORT</p><h1>{}</h1>{}</main><footer>Offline case report · keep this directory with its raw and normalized evidence.</footer></body></html>",
        escape(title),
        escape(title),
        content
    )?;
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

const STYLE: &str = "*{box-sizing:border-box}body{margin:0;background:#101923;color:#e9f1f5;font:16px/1.5 system-ui,sans-serif}header,main,footer{padding:24px max(24px,calc((100vw - 1200px)/2))}header{border-bottom:1px solid #355061;background:#172633}.brand,.eyebrow{color:#59d5d0;font:700 12px/1.4 ui-monospace,monospace;letter-spacing:.15em}nav{display:flex;flex-wrap:wrap;gap:8px 24px}a{color:#59d5d0}a:focus-visible{outline:3px solid #f1bd68;outline-offset:3px}h1{font-size:clamp(2rem,5vw,4rem);line-height:1.1;margin:.25em 0 .8em}p{max-width:75ch;color:#a7bcc8}.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px}.cards div{background:#172633;border:1px solid #355061;border-radius:8px;padding:20px}.cards strong{display:block;color:#e9f1f5;font-size:2rem}.cards span{color:#a7bcc8}.scroll{overflow-x:auto}table{width:100%;border-collapse:collapse;min-width:750px}th,td{text-align:left;vertical-align:top;padding:10px;border-bottom:1px solid #355061;overflow-wrap:anywhere}th{background:#1d3141;color:#e9f1f5}tr:nth-child(even){background:#172633}td{font:13px/1.5 ui-monospace,monospace}footer{border-top:1px solid #355061;color:#a7bcc8;font-size:13px}";
const GRAPH_STYLE: &str = ".breakdown{margin:32px 0;padding:24px;background:#172633;border:1px solid #355061;border-radius:8px}.breakdown h2{margin:0 0 16px}.breakdown label{display:grid;grid-template-columns:1fr auto;gap:4px 20px;margin:12px 0;color:#a7bcc8}.breakdown label span{color:#e9f1f5;font-family:ui-monospace,monospace}.breakdown meter{grid-column:1/-1;width:100%;height:18px}.breakdown meter::-webkit-meter-bar{background:#1d3141;border:1px solid #355061}.breakdown meter::-webkit-meter-optimum-value{background:#59d5d0}";
const TABLE_STYLE: &str = ".evidence-table{min-width:1600px;table-layout:fixed}.evidence-table th:nth-child(1){width:190px}.evidence-table th:nth-child(2){width:150px}.evidence-table th:nth-child(3){width:160px}.evidence-table th:nth-child(4){width:160px}.evidence-table th:nth-child(5){width:250px}.evidence-table th:nth-child(6){width:480px}.evidence-table th:nth-child(7){width:130px}.evidence-table th:nth-child(8){width:80px}";

#[cfg(test)]
mod tests {
    use super::escape;
    #[test]
    fn escapes_collected_text() {
        assert_eq!(escape("<script x='&'>"), "&lt;script x=&#39;&amp;&#39;&gt;");
    }
}
