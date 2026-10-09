"use strict";
(() => {
  const view = document.body.dataset.view;
  const data = window.caseData;
  const all = window.caseEvents;
  const $ = (id) => document.getElementById(id);
  const el = (tag, text, className) => {
    const node = document.createElement(tag);
    if (text !== undefined) node.textContent = String(text);
    if (className) node.className = className;
    return node;
  };
  const fmt = (value) => Number(value).toLocaleString("en-US");
  const knownTime = (value) => value && /(?:Z|[+-]\d\d:\d\d)$/.test(value) ? Date.parse(value) : NaN;
  const manifest = new Map(data.manifest.map((file) => [file.path, file]));
  $("case-name").textContent = data.name;
  $("case-info").textContent = `Operator: ${data.info.operator || "unknown"} | Started: ${data.info.started_at || "unknown"}`;
  for (const [key, label, target] of [["events", "Events", "timeline"], ["uploads", "Upload records", "exfil"], ["completed", "Completed uploads", "exfil"], ["downloads", "Download records", "downloads"], ["failed", "Failed sources", "collection"]]) {
    const link = el("a"); link.href = `${target}.html${key === "completed" ? "?status=completed" : key === "failed" ? "?status=failed" : ""}`;
    link.append(el("strong", fmt(data.counts[key])), el("small", label));
    $("totals").append(link);
  }
  const transferView = ["index", "exfil", "downloads"].includes(view);
  const coverageView = view === "collection";
  const evidenceView = view === "evidence";
  let base = coverageView ? data.coverage : evidenceView ? data.manifest : all.filter((event) => {
    if (view === "exfil") return event.transfer?.direction === "upload";
    if (view === "downloads") return event.transfer?.direction === "download" || event.kind === "download";
    if (view === "index") return event.transfer || event.kind === "download";
    if (view === "network") return event.transfer || ["network-lead", "active-connection", "connection-closed", "inbound-listener", "packet", "browser-visit"].includes(event.kind);
    return true;
  });
  const ids = new Map(all.map((event, index) => [event, index + 1]));
  base = base.map((row, index) => ({row, index, id: ids.get(row), time: knownTime(row.timestamp || row.acquired_at)}));
  $("records-title").textContent = view === "index" ? "Transfer records" : coverageView ? "Coverage records" : evidenceView ? "Raw evidence index" : "Records";
  $("packets").parentElement.hidden = view !== "timeline";
  for (const id of ["application", "from", "until", "sort"]) {
    if (coverageView || evidenceView) $(id).parentElement.hidden = true;
  }
  if (evidenceView) $("status").parentElement.hidden = true;
  const selectors = {
    application: (row) => row.application || "Unattributed",
    source: (row) => row.source || "Unknown",
    status: (row) => row.state || row.transfer?.status || row.level || "Unknown"
  };
  for (const [id, value] of Object.entries(selectors)) {
    for (const option of [...new Set(base.map(({row}) => value(row)))].sort()) {
      const node = el("option", option); node.value = option; $(id).append(node);
    }
  }
  const selectedStatus = new URLSearchParams(location.search).get("status");
  if (["completed", "failed"].includes(selectedStatus) && ![...$("status").options].some((option) => option.value === selectedStatus)) {
    const option = el("option", selectedStatus); option.value = selectedStatus; $("status").append(option);
  }
  if (selectedStatus && [...$("status").options].some((option) => option.value === selectedStatus)) $("status").value = selectedStatus;
  const headings = coverageView ? ["Source", "Status", "Detail"] : evidenceView ? ["Original source", "Acquired", "Bytes", "SHA-256", "Retained raw file"] : transferView ? ["Time", "Application / user", "File / object", "Destination / peer", "Bytes", "Outcome", "Direction / perspective", "Evidence"] : ["Time", "Application / user", "Activity", "Destination / path", "Detail", "Evidence"];
  const header = el("tr");
  for (const text of headings) { const th = el("th", text); th.scope = "col"; header.append(th); }
  $("table").querySelector("thead").append(header);
  let page = 0, matches = [], timer, lastFilterKey;
  const sub = (cell, text) => { if (text) cell.append(el("span", text, "sub")); };
  function rawLink(path) {
    if (!manifest.has(path) || !path.startsWith("raw/") || path.split("/").some((part) => ["", ".", ".."].includes(part))) return el("span", "Raw file unavailable");
    const link = el("a", path); link.href = `../${path.split("/").map(encodeURIComponent).join("/")}`; link.download = path.split("/").pop();
    return link;
  }
  function reference(event, id) {
    const detail = el("details");
    detail.append(el("summary", `Record ${id}${event.evidence_line ? ` · raw line ${event.evidence_line}` : ""}`));
    detail.append(el("p", manifest.get(event.evidence)?.source || event.evidence));
    detail.append(rawLink(event.evidence));
    detail.append(el("pre", event.detail));
    detail.append(el("span", `Original time: ${event.timestamp || "unknown"}`, "sub"));
    detail.append(el("span", `Source: ${event.source} | Evidence: ${event.level}`, "sub"));
    return detail;
  }
  function addRow({row, id}) {
    const tr = el("tr");
    const cell = (text, cls) => { const td = el("td", text, cls); tr.append(td); return td; };
    if (coverageView) {
      cell(row.source); cell(row.state, `status ${row.state}`); cell(row.detail);
    } else if (evidenceView) {
      cell(row.source); cell(row.acquired_at, "time"); cell(fmt(row.bytes), "bytes"); cell(row.sha256, "hash"); cell().append(rawLink(row.path));
    } else {
      const time = knownTime(row.timestamp);
      const stamp = cell(Number.isFinite(time) ? new Date(time).toISOString().replace("T", " ").replace("Z", " UTC") : row.timestamp || "Unknown time", "time");
      stamp.title = row.timestamp || "No source timestamp";
      if (row.timestamp && !Number.isFinite(knownTime(row.timestamp))) sub(stamp, "Source-local time; timezone not retained");
      const app = cell(row.application || "Unattributed"); sub(app, `User: ${row.user || "not retained"}`);
      if (transferView) {
        const t = row.transfer || {};
        cell(t.file || (row.kind === "download" ? row.destination : null) || "Original file not retained");
        const target = cell(t.target || "Not retained"); sub(target, t.peer ? `Peer: ${t.peer}` : null);
        const bytes = cell(t.bytes === null || t.bytes === undefined ? "Not retained" : fmt(t.bytes), "bytes"); sub(bytes, t.bytes_basis);
        const outcome = t.status || "recorded"; cell(outcome, `status ${outcome}`);
        const flow = cell(t.direction || "download");
        sub(flow, t.perspective === "server" ? `Server: ${t.direction === "upload" ? "inbound" : "outbound"}` : t.perspective === "client" ? `Client: ${t.direction === "upload" ? "outbound" : t.direction === "download" ? "inbound" : "unknown"}` : "Perspective unknown");
        sub(flow, [t.protocol, t.method].filter(Boolean).join(" / "));
      } else {
        const kind = cell(row.kind.replaceAll("-", " ")); sub(kind, row.source);
        cell(row.destination || "Not retained"); cell(row.detail);
      }
      cell().append(reference(row, id));
    }
    return tr;
  }
  function render() {
    const size = Number($("page-size").value);
    const pages = Math.max(1, Math.ceil(matches.length / size)); page = Math.min(page, pages - 1);
    const tbody = $("table").querySelector("tbody"); tbody.replaceChildren();
    for (const row of matches.slice(page * size, (page + 1) * size)) tbody.append(addRow(row));
    if (!matches.length) { const tr = el("tr"), td = el("td", base.length ? "No records match these filters." : "No records retained for this section. Review source coverage and imported application logs.", "empty"); td.colSpan = headings.length; tr.append(td); tbody.append(tr); }
    $("result-count").textContent = `${fmt(matches.length)} matching / ${fmt(base.length)} records in this section. Complete case: ${fmt(all.length)} events.`;
    $("page-position").textContent = `Page ${page + 1} of ${pages}`;
    $("previous").disabled = page === 0; $("next").disabled = page + 1 >= pages;
  }
  function filter() {
    const key = JSON.stringify([...$("filters").elements].map((input) => [input.id, input.value, input.checked]));
    if (key === lastFilterKey) return;
    lastFilterKey = key;
    const query = $("search").value.trim().toLowerCase();
    const from = $("from").value ? Date.parse(`${$("from").value}Z`) : null;
    const until = $("until").value ? Date.parse(`${$("until").value}Z`) : null;
    matches = base.filter(({row, time}) => {
      if (view === "timeline" && !$("packets").checked && row.kind === "packet") return false;
      for (const [id, value] of Object.entries(selectors)) { if (!$(id).parentElement.hidden && $(id).value && value(row) !== $(id).value) return false; }
      if ((from !== null || until !== null) && (!Number.isFinite(time) || (from !== null && time < from) || (until !== null && time > until))) return false;
      const original = manifest.get(row.evidence)?.source || "";
      return !query || `${JSON.stringify(row)} ${original}`.toLowerCase().includes(query);
    });
    const order = $("sort").value;
    if (!coverageView && !evidenceView && order !== "collection") matches.sort((a, b) => {
      const x = Number.isFinite(a.time), y = Number.isFinite(b.time);
      if (x !== y) return x ? -1 : 1;
      return x && a.time !== b.time ? (a.time - b.time) * (order === "newest" ? -1 : 1) : a.index - b.index;
    });
    page = 0; render();
  }
  $("filters").addEventListener("submit", (event) => event.preventDefault());
  $("filters").addEventListener("input", () => { clearTimeout(timer); timer = setTimeout(filter, 150); });
  $("filters").addEventListener("change", () => { clearTimeout(timer); filter(); });
  $("filters").addEventListener("reset", () => setTimeout(filter, 0));
  $("page-size").addEventListener("change", () => { page = 0; render(); });
  $("previous").addEventListener("click", () => { page--; render(); });
  $("next").addEventListener("click", () => { page++; render(); });
  filter();
})();
