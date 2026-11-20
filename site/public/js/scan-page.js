// Agent Guard /scan page: collects input, talks to the scanner Web Worker, and
// renders the findings JSON. Report content comes from scanned (possibly hostile)
// material, so it is only ever inserted as text nodes — never as HTML — and only
// https: links are created.
const root = document.getElementById("scanner");
if (root) main(root);

function main(root) {
  root.hidden = false;
  const SEVERITIES = ["critical", "high", "medium", "low", "info"];
  const MAX_FILES = 5000;
  const MAX_FILE_BYTES = 2 * 1024 * 1024;
  const MAX_TOTAL_BYTES = 64 * 1024 * 1024;
  const SKIP_DIRS = new Set([".git", "node_modules", ".venv", "venv", ".tox", ".mypy_cache", ".pytest_cache"]); // __pycache__ is scanned (AG-HYG-004)
  const ARCHIVE = /\.(zip|tgz|tar\.gz|tar)$/i;
  const siteBase = root.dataset.worker.replace(/\/js\/scan-worker\.js$/, "");
  // Sign-in and saved scans (public/js/account.js), when the site is built with a Supabase project.
  const account = window.agentguardAccount?.enabled ? window.agentguardAccount : null;

  const $ = (id) => document.getElementById(id);
  const status = $("status"), statusText = $("status-text"), errorBox = $("error"), result = $("result");

  // -- worker plumbing ---------------------------------------------------------
  let worker = null;
  let seq = 0;
  const pending = new Map();

  function getWorker() {
    if (worker) return worker;
    worker = new Worker(root.dataset.worker, { type: "module", name: "agentguard-scanner" });
    worker.onmessage = (ev) => {
      const msg = ev.data;
      const p = pending.get(msg.id);
      if (!p) return;
      if (msg.type === "progress") return p.onProgress?.(msg);
      pending.delete(msg.id);
      if (msg.type === "error") p.reject(msg);
      else p.resolve(msg);
    };
    worker.onerror = (ev) => {
      ev.preventDefault();
      failAll({ message: "The scanner could not start in this browser." });
    };
    return worker;
  }

  function call(msg, onProgress, transfer = []) {
    const id = ++seq;
    return new Promise((resolve, reject) => {
      pending.set(id, { resolve, reject, onProgress });
      getWorker().postMessage({ ...msg, id, engineSha: root.dataset.engineSha }, transfer);
    });
  }

  // Test hook: lists the worker's network requests (resource timing). Read-only.
  window.agentguardNetLog = () => (worker ? call({ type: "net-log" }).then((r) => r.urls) : Promise.resolve([]));

  function failAll(err) {
    for (const p of pending.values()) p.reject(err);
    pending.clear();
  }

  $("cancel").addEventListener("click", () => {
    if (powWorker) { powWorker.terminate(); powWorker = null; }
    if (events) { events.close(); events = null; busy = false; status.hidden = true; }
    if (worker) worker.terminate();
    worker = null;
    failAll({ message: "Cancelled.", cancelled: true });
  });

  // Warm the engine up as soon as someone starts using the form.
  let warmed = false;
  root.addEventListener("focusin", () => {
    if (warmed) return;
    warmed = true;
    call({ type: "init" }).catch(() => { warmed = false; });
  });

  // -- tabs ----------------------------------------------------------------------
  const tabs = [...root.querySelectorAll('[role="tab"]')];
  function selectTab(tab, focus) {
    for (const t of tabs) {
      const on = t === tab;
      t.setAttribute("aria-selected", String(on));
      t.tabIndex = on ? 0 : -1;
      $(t.getAttribute("aria-controls")).hidden = !on;
    }
    placeFeedback();
    if (focus) tab.focus();
  }

  // Progress and errors sit right under the active tab's input (its form, or the drop zone),
  // where the eye is after pressing Scan, instead of below the explanations further down.
  function placeFeedback() {
    const panel = root.querySelector('[role="tabpanel"]:not([hidden])');
    const anchor = panel?.querySelector("form, .drop");
    if (anchor && anchor.nextElementSibling !== status) anchor.after(status, errorBox);
  }
  placeFeedback();
  tabs.forEach((t, i) => {
    t.addEventListener("click", () => selectTab(t, false));
    t.addEventListener("keydown", (e) => {
      const d = { ArrowRight: 1, ArrowLeft: -1, Home: -i, End: tabs.length - 1 - i }[e.key];
      if (d === undefined) return;
      e.preventDefault();
      selectTab(tabs[(i + d + tabs.length) % tabs.length], true);
    });
  });

  // -- running a scan --------------------------------------------------------------
  let busy = false;

  async function run(msg, label, transfer) {
    if (busy) return;
    busy = true;
    errorBox.hidden = true;
    result.hidden = true;
    status.hidden = false;
    statusText.textContent = "Starting the scanner…";
    try {
      const res = await call(msg, (p) => { statusText.textContent = p.detail ? `${p.stage}: ${p.detail}` : `${p.stage}…`; }, transfer);
      renderReport(JSON.parse(res.report), res.meta || {}, label);
    } catch (err) {
      showError(err);
    } finally {
      busy = false;
      status.hidden = true;
    }
  }

  function showError(err) {
    errorBox.replaceChildren(el("p", {}, err.message || String(err)));
    if (err.signedOut) {
      const next = location.pathname + location.search;
      errorBox.append(el("p", {}, el("a", { class: "btn small", href: `${siteBase}/signin/?next=${encodeURIComponent(next)}` }, "Sign in")));
    }
    if (err.supported?.length) {
      errorBox.append(el("p", {}, "Supported inputs:"), el("ul", {}, ...err.supported.map((s) => el("li", {}, s))));
    }
    errorBox.hidden = false;
  }

  // -- Agent Guard Web server (same origin, /api/) -----------------------------------
  // Links go to the server when it is reachable (cached, shareable reports); pasted
  // text and dropped files never do. Without a server, GitHub links scan in the browser.
  const KEY = /^[0-9a-f]{32}$/;
  let serverCheck = null;
  // The server's health document (engine, current rule pack, proof-of-work difficulty), or null.
  function serverInfo() {
    serverCheck ??= fetch(`${siteBase}/api/health`, { cache: "no-store", credentials: "omit" })
      .then((r) => (r.ok ? r.json() : null)).then((j) => (j && j.ok ? j : null)).catch(() => null);
    return serverCheck;
  }
  let events = null;
  let powWorker = null;

  // Bot check for requests that start work on the server: a short computation on this
  // device (see pow.js). No third party is involved and nothing is sent except the answer.
  async function proofOfWork() {
    const r = await fetch(`${siteBase}/api/challenge`, { cache: "no-store", credentials: "omit" });
    if (!r.ok) throw { message: `The server returned HTTP ${r.status}.` };
    const ch = await r.json();
    if (!ch.difficulty) return null;
    statusText.textContent = "Checking this is a browser, not a bot (a moment of computation on your device)…";
    return new Promise((resolve, reject) => {
      powWorker = new Worker(`${siteBase}/js/pow-worker.js`, { type: "module", name: "agentguard-bot-check" });
      powWorker.onmessage = (ev) => {
        powWorker.terminate();
        powWorker = null;
        if (ev.data.nonce) resolve({ challenge: ch.challenge, nonce: ev.data.nonce });
        else reject({ message: "The bot check failed. Reload the page and try again." });
      };
      powWorker.onerror = (ev) => {
        ev.preventDefault();
        powWorker?.terminate();
        powWorker = null;
        reject({ message: "The bot check could not run in this browser." });
      };
      powWorker.postMessage({ challenge: ch.challenge, difficulty: ch.difficulty });
    });
  }

  async function postJob(path, body) {
    const pow = await proofOfWork();
    statusText.textContent = "Sending to Agent Guard Web…";
    const r = await fetch(`${siteBase}${path}`, {
      method: "POST", credentials: "omit", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ ...body, pow }),
    });
    const job = await r.json().catch(() => ({}));
    if (!r.ok) throw { message: job.error || `The server returned HTTP ${r.status}.`, supported: job.supported };
    return job;
  }

  function waitForJob(job) {
    return new Promise((resolve, reject) => {
      events = new EventSource(`${siteBase}/api/scans/${job.id}/events`);
      events.onmessage = (ev) => {
        const j = JSON.parse(ev.data);
        if (j.detail) statusText.textContent = j.detail;
        if (j.status === "done" || j.status === "error") { events.close(); resolve(j); }
      };
      events.onerror = () => { events.close(); reject({ message: "Lost contact with the server." }); };
    });
  }

  // Runs one server job (scan, rescan or response check) and hands the finished job to onDone.
  async function serverTask(path, body, onDone, { keepResult = false } = {}) {
    if (busy) return;
    busy = true;
    errorBox.hidden = true;
    if (!keepResult) result.hidden = true;
    status.hidden = false;
    statusText.textContent = "Contacting Agent Guard Web…";
    try {
      const final = await waitForJob(await postJob(path, body));
      if (final.status === "error") throw { message: final.error, supported: final.supported };
      await onDone(final);
    } catch (err) {
      showError(err);
    } finally {
      events = null;
      busy = false;
      status.hidden = true;
    }
  }

  async function loadServerReport(key, label, detail) {
    const opts = { credentials: "omit" };
    const [r, resp, server] = await Promise.all([
      fetch(`${siteBase}/api/reports/${key}`, opts),
      fetch(`${siteBase}/api/reports/${key}/response`, opts).then((x) => (x.ok ? x.json() : {})).catch(() => ({})),
      serverInfo(),
    ]);
    if (!r.ok) throw { message: r.status === 404 ? "That report does not exist or has expired." : `The server returned HTTP ${r.status}.` };
    const u = new URL(location.href);
    u.searchParams.delete("url");
    u.searchParams.set("report", key);
    history.replaceState(null, "", u);
    renderReport(await r.json(), { serverKey: key, cached: detail?.cached, notice: detail?.notice, response: resp.response, server }, label);
  }

  function runServer(input) {
    return serverTask("/api/scans", { input }, (final) => loadServerReport(final.report_key, input, final));
  }

  // Link
  const linkInput = $("link");
  const qs = new URLSearchParams(location.search).get("url");
  if (qs) linkInput.value = qs.slice(0, 2048);
  $("link-form").addEventListener("submit", (e) => {
    e.preventDefault();
    const url = linkInput.value.trim();
    if (!url) return;
    const u = new URL(location.href);
    u.searchParams.set("url", url);
    u.searchParams.delete("report");
    history.replaceState(null, "", u);
    serverInfo().then((info) => (info ? runServer(url) : run({ type: "scan-link", url }, url)));
  });
  const permalink = new URLSearchParams(location.search).get("report");
  if (permalink && KEY.test(permalink)) {
    status.hidden = false;
    statusText.textContent = "Loading the report…";
    loadServerReport(permalink, "").catch(showError).finally(() => { status.hidden = true; });
  }

  // A report saved to My scans (?saved=<id>): read from the signed-in user's account.
  const savedId = new URLSearchParams(location.search).get("saved");
  if (savedId && account) {
    status.hidden = false;
    statusText.textContent = "Loading the saved scan…";
    account.ready.then(() => account.getScan(savedId))
      .then((row) => renderReport(row.report, { saved: row }, row.label))
      .catch(showError)
      .finally(() => { status.hidden = true; });
  }

  // Paste
  $("paste-form").addEventListener("submit", (e) => {
    e.preventDefault();
    const text = $("paste-text").value;
    if (!text.trim()) return;
    run({ type: "scan-text", text, name: $("paste-kind").value || undefined }, "Pasted text");
  });

  // Files
  const drop = $("drop");
  drop.addEventListener("dragover", (e) => { e.preventDefault(); drop.classList.add("over"); });
  drop.addEventListener("dragleave", () => drop.classList.remove("over"));
  drop.addEventListener("drop", async (e) => {
    e.preventDefault();
    drop.classList.remove("over");
    const entries = [...e.dataTransfer.items].map((it) => it.webkitGetAsEntry?.()).filter(Boolean);
    if (entries.length) scanEntries(entries);
    else scanFileList([...e.dataTransfer.files].map((f) => ({ path: f.name, file: f })));
  });
  drop.addEventListener("keydown", (e) => {
    if (e.key === "Enter" || e.key === " ") { e.preventDefault(); $("pick-files").click(); }
  });
  $("pick-files").addEventListener("change", (e) => scanFileList([...e.target.files].map((f) => ({ path: f.name, file: f }))));
  $("pick-folder").addEventListener("change", (e) => scanFileList([...e.target.files].map((f) => ({ path: f.webkitRelativePath || f.name, file: f }))));

  async function scanEntries(entries) {
    const list = [];
    const events = [];
    const readDir = (dir) => new Promise((resolve, reject) => {
      const reader = dir.createReader();
      const all = [];
      const next = () => reader.readEntries((batch) => (batch.length ? (all.push(...batch), next()) : resolve(all)), reject);
      next();
    });
    async function walk(entry, depth) {
      if (list.length > MAX_FILES) return;
      if (entry.isFile) {
        list.push({ path: entry.fullPath.replace(/^\//, ""), file: await new Promise((res, rej) => entry.file(res, rej)) });
      } else if (entry.isDirectory && !SKIP_DIRS.has(entry.name) && depth < 32) {
        for (const child of await readDir(entry)) await walk(child, depth + 1);
      }
    }
    try {
      for (const entry of entries) await walk(entry, 0);
    } catch {
      events.push({ kind: "unreadable", path: "(dropped folder)", detail: "the browser could not read part of the folder" });
    }
    scanFileList(list, events);
  }

  async function scanFileList(list, events = []) {
    if (!list.length) return;
    if (list.length === 1 && ARCHIVE.test(list[0].path)) {
      const data = await list[0].file.arrayBuffer();
      return run({ type: "scan-archive", name: list[0].path, data }, list[0].path, [data]);
    }
    const files = [];
    let total = 0;
    for (const { path, file } of list) {
      if (path.split("/").slice(0, -1).some((seg) => SKIP_DIRS.has(seg))) continue;
      if (files.length >= MAX_FILES) { events.push({ kind: "too_many_files", path, detail: `more than ${MAX_FILES} files` }); break; }
      if (file.size > MAX_FILE_BYTES) { events.push({ kind: "too_large", path, detail: `${file.size} bytes` }); continue; }
      if (total + file.size > MAX_TOTAL_BYTES) { events.push({ kind: "total_bytes_exceeded", path }); continue; }
      total += file.size;
      files.push({ path, data: await file.arrayBuffer() });
    }
    const label = list.length === 1 ? list[0].path : `${files.length} dropped file(s)`;
    run({ type: "scan-files", files, events, label }, label, files.map((f) => f.data));
  }

  // -- rendering -------------------------------------------------------------------
  function el(tag, attrs = {}, ...children) {
    const node = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs)) {
      if (v === undefined || v === null || v === false) continue;
      if (k === "class") node.className = v;
      else if (k === "href") {
        const safe = safeHref(v);
        if (safe) { node.setAttribute("href", safe); if (/^https:/.test(safe)) node.setAttribute("rel", "noopener noreferrer"); }
      } else node.setAttribute(k, v === true ? "" : String(v));
    }
    for (const c of children.flat()) if (c !== null && c !== undefined && c !== false) node.append(c instanceof Node ? c : String(c));
    return node;
  }

  function safeHref(v) {
    try {
      const u = new URL(v, location.href);
      if (u.protocol === "https:" || (u.origin === location.origin && u.protocol === location.protocol)) return u.href;
    } catch { /* not a URL */ }
    return null;
  }

  function sevBadge(sev) { return el("span", { class: `sev ${sev}` }, sev); }

  // The report's target: the immutable reference it was resolved to (kind, locator, resolved commit or version).
  function targetRef(report) {
    const t = report.target || {};
    return { ...(t.ref || {}), kind: t.ref?.kind || t.kind, commit: t.commit };
  }

  function locationUrl(ref, loc) {
    if (!ref?.source_url_template || !ref.resolved || !loc?.file || loc.container) return null;
    const path = loc.file.split("/").map(encodeURIComponent).join("/");
    return ref.source_url_template.replace("{resolved}", ref.resolved).replace("{path}", path).replace("{line}", String(loc.start?.line || 1));
  }

  // A finding's location (file, line; the archive or image it is inside, when it is) and an evidence span.
  function where(loc) { return loc ? `${loc.container ? loc.container + " › " : ""}${loc.file}:${loc.start?.line ?? 1}` : ""; }
  function whereSpan(span) { return span ? `${span.path}:${span.start_line ?? 1}` : ""; }

  function renderTarget(report, meta, label) {
    const t = targetRef(report);
    if (t.kind === "github" && t.resolved) {
      const [owner, repo, ...sub] = t.locator.split("/");
      const url = `https://github.com/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/tree/${t.resolved}/${sub.map(encodeURIComponent).join("/")}`;
      return el("p", {}, "Scanned ", el("a", { href: url }, `${owner}/${repo}${sub.length ? "/" + sub.join("/") : ""}`),
        " at commit ", el("code", {}, t.resolved.slice(0, 12)), ".");
    }
    if (t.kind === "gist" && t.resolved) {
      return el("p", {}, "Scanned gist ", el("a", { href: `https://gist.github.com/${encodeURIComponent(t.locator)}/${t.resolved}` }, t.locator), " at revision ", el("code", {}, t.resolved.slice(0, 12)), ".");
    }
    if ((t.kind === "npm" || t.kind === "pypi") && t.resolved) {
      const url = t.kind === "npm"
        ? `https://www.npmjs.com/package/${t.locator.split("/").map(encodeURIComponent).join("/")}/v/${encodeURIComponent(t.resolved)}`
        : `https://pypi.org/project/${encodeURIComponent(t.locator)}/${encodeURIComponent(t.resolved)}/`;
      return el("p", {}, `Scanned ${t.kind} package `, el("a", { href: url }, `${t.locator} ${t.resolved}`),
        t.integrity ? [" (", el("code", {}, String(t.integrity).slice(0, 19) + "…"), ")"] : null, ".");
    }
    if (t.kind === "remote_mcp") {
      return el("p", {}, "Checked the remote MCP server ", el("code", {}, t.locator),
        " as an unauthenticated, read-only client (discovery and list methods, OAuth metadata; never tools/call). Metadata fingerprint ",
        el("code", {}, String(t.resolved || "").replace(/^sha256:/, "").slice(0, 12)),
        ". A remote server can change its tools at any time; this report shows what it returned when checked.");
    }
    return el("p", {}, "Scanned ", meta.name ? el("code", {}, meta.name) : label, ".");
  }

  const plural = (n, word) => `${n} ${word}${n === 1 ? "" : "s"}`;

  // One cell of the facts row under the report's top: a label, a large value and a note.
  function stat(label, value, sub) {
    return el("div", {}, el("dt", {}, label), el("dd", {}, el("span", { class: "v" }, String(value)), sub ? el("span", { class: "sub" }, sub) : null));
  }

  // spec/interfaces.md §8: the verdict is rule-based; the score never decides it alone.
  const VERDICT_TEXT = {
    ALLOW: ["Nothing that counts towards the verdict matched.",
      "ALLOW does not mean safe: static rules miss paraphrased or novel attacks, and behaviour that only appears at run time."],
    REVIEW: ["Review this before installing or enabling it.", "At least one finding needs a person to look at it."],
    BLOCK: ["Do not install or enable this.", "At least one finding is strong enough to block on its own."],
  };
  const TIER_TEXT = {
    L0: "only adds instructions", L1: "writes files in the workspace", L2: "uses shell, network or credentials",
    L3: "persistent, system-level, financial or destructive",
  };
  const FIX_LABEL = { auto: "Auto-fix available", patch: "Proposed patch", guidance: "Guidance", remove: "Do not install", none: "No fix" };
  const MAP_LABEL = {
    owasp_asi: "OWASP Agentic", owasp_mcp: "OWASP MCP", owasp_ast: "OWASP Skills", owasp_llm: "OWASP LLM", nsa_csi_mcp: "NSA MCP CSI",
    cwe: "CWE", skilltrustbench: "SkillTrustBench", malskillbench: "MalSkillBench", mitre_atlas: "MITRE ATLAS",
  };

  function renderReport(report, meta, label) {
    const findings = (report.findings || []).filter((f) => !f.suppressed);
    const tool = report.tool || {};
    const cov = report.coverage || {};
    const counts = Object.fromEntries(SEVERITIES.map((s) => [s, findings.filter((f) => f.severity === s).length]));
    const files = cov.files_total ?? report.stats?.files_scanned ?? 0;
    const components = report.inventory?.length ?? 0;
    const counting = findings.filter((f) => f.corroborated !== false && f.category !== "hygiene").length;
    const verdict = VERDICT_TEXT[report.verdict] ? report.verdict : "ALLOW";
    const [head, note] = VERDICT_TEXT[verdict];
    const reasons = (report.verdict_reasons || []).slice(0, 4);

    const verdictBox = el("div", { class: `verdict${verdict === "ALLOW" ? "" : " hot"}` },
      el("strong", {}, `${verdict}: ${head}`), note,
      reasons.length ? el("ul", { class: "verdict-reasons" }, ...reasons.map((r) => el("li", {}, r))) : null);
    const summary = findings.length
      ? `${plural(findings.length, "finding")}: ${SEVERITIES.filter((s) => counts[s]).map((s) => `${counts[s]} ${s}`).join(", ")}`
      : `No findings from ${report.stats?.rules_evaluated ?? tool.rule_count} rules`;
    const board = el("div", { class: "board corners" },
      el("div", { class: "board-head" }, el("span", { class: "summary" }, summary),
        el("span", { class: "accent" }, `Score ${report.score ?? 0} · tier ${report.risk_tier || "L0"}`)),
      el("ul", { class: "sev-counts", "aria-label": "Findings by severity" }, ...SEVERITIES.map((s) =>
        el("li", { class: `sev-count ${s}${counts[s] ? "" : " zero"}` }, el("span", { class: "n" }, String(counts[s])), sevBadge(s)))),
      el("p", { class: "board-note" }, `${plural(counting, "finding")} count${counting === 1 ? "s" : ""} towards the verdict · `
        + `${plural(files, "file")} and ${plural(components, "component")} scanned`));

    const pct = Math.round((cov.analyzability ?? 1) * 1000) / 10;
    const facts = el("dl", { class: "report-facts" },
      stat("Verdict", verdict, `score ${report.score ?? 0} of 100 · ${report.policy || "balanced"} policy`),
      stat("Risk tier", report.risk_tier || "L0", TIER_TEXT[report.risk_tier] || ""),
      stat("Coverage", `${pct}%`, `${cov.files_analysed ?? files} of ${plural(files, "file")} analysed`),
      stat("Rule pack", `v${tool.rule_pack}`, `${tool.rules_implemented ?? tool.rule_count} rules · digest ${String(tool.rule_pack_digest || "").slice(0, 12)}`),
      stat("Engine", tool.version, meta.saved
        ? `Saved to My scans ${new Date(meta.saved.created_at).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" })}`
        : meta.serverKey
        ? `Agent Guard Web, in an isolated sandbox${meta.cached ? " (cached result for this exact version and rule pack)" : ""}`
        : `Run on this device · ${report.profile || "quick"} profile`),
      meta.scan_ms ? stat("Scan time", `${(meta.scan_ms / 1000).toFixed(1)} s`,
        meta.fetch_ms !== undefined ? `Fetched from GitHub in ${(meta.fetch_ms / 1000).toFixed(1)} s` : "On this device") : null);

    const extra = [];
    if (meta.serverKey) {
      const link = new URL(`${siteBase}/scan/`, location.href);
      link.searchParams.set("report", meta.serverKey);
      const copy = el("button", { type: "button", class: "btn secondary small" }, "Copy link");
      copy.addEventListener("click", () => navigator.clipboard?.writeText(link.href).then(() => { copy.textContent = "Copied"; }));
      extra.push(el("p", { class: "small" }, "Permalink (unlisted; anyone with the link can view it): ", el("a", { href: link.href }, link.href), " ", copy));
      if (meta.notice) extra.push(el("p", { class: "notice" }, meta.notice));
      if (meta.response) extra.push(renderResponse(meta.response));
      extra.push(renderServerActions(report, meta, label));
    }

    const parts = [el("div", { class: "report corners" },
      el("div", { class: "report-top" },
        el("div", { class: "report-intro" }, el("h2", { id: "result-title", tabindex: "-1" }, "Report"), renderTarget(report, meta, label), verdictBox),
        board),
      facts,
      renderDownloads(meta, report),
      account ? renderSave(report, meta, label) : null,
      extra.length ? el("div", { class: "report-extra" }, ...extra) : null,
      el("div", { class: "plans-foot", "aria-hidden": "true" }))];

    const artifacts = (report.artifacts || []).filter((a) => a.type !== "repository" || a.findings);
    if (artifacts.length) {
      parts.push(el("h3", { class: "report-h" }, "Components"),
        el("div", { class: "corners" }, el("div", { class: "table-scroll" }, el("table", { class: "rules-table components-table" },
          el("thead", {}, el("tr", {}, ...["Component", "Verdict", "Risk tier", "Can do", "Findings"].map((h) => el("th", { scope: "col" }, h)))),
          el("tbody", {}, ...artifacts.map((a) => el("tr", {},
            el("td", {}, el("code", {}, a.id), el("span", { class: "muted small" }, ` ${a.type}${a.ecosystem ? " · " + a.ecosystem : ""}`)),
            el("td", {}, a.verdict, a.triage !== undefined && a.triage !== null
              ? el("span", { class: "muted small", title: "Triage model (advisory): probability that the component is malicious" }, ` · triage ${a.triage.toFixed(2)}`) : null),
            el("td", { title: TIER_TEXT[a.risk_tier] || "" }, a.risk_tier),
            el("td", { class: "muted" }, (a.capabilities || []).join(", ") || "—"),
            el("td", {}, String(a.findings ?? 0)))))))));
    }

    if (report.chains?.length) {
      const byFp = Object.fromEntries(findings.map((f) => [f.fingerprint, f]));
      parts.push(el("details", { class: "coverage", open: true },
        el("summary", {}, `Attack chains: ${report.chains.length}`),
        el("ol", {}, ...report.chains.map((ch) => el("li", {}, sevBadge(ch.severity), " ",
          ...(ch.steps || []).map((fp) => byFp[fp]).filter(Boolean).flatMap((f, i) => [i ? " → " : "", el("code", {}, f.id), ` ${where(f.location)}`]),
          ch.sink ? el("span", { class: "muted" }, ` (ends in ${ch.sink})`) : null)))));
    }

    if (report.flows?.length) {
      const names = Object.fromEntries((report.inventory || []).map((c) => [c.id, c.name]));
      // Each flow comes from one finding (report.flows is the findings' flow paths): its title
      // and rule sit beside the diagram.
      parts.push(el("h3", { class: "report-h" }, "Dangerous combinations"),
        el("ul", { class: "flows corners" }, ...report.flows.map((fl) => {
          const f = findings.find((x) => x.flow?.narrative === fl.narrative);
          return el("li", { class: fl.nodes.length > 2 ? "long" : null },
            el("div", {},
              f ? el("p", { class: "flow-title" }, sevBadge(f.severity), el("strong", {}, f.title)) : null,
              fl.narrative ? el("p", { class: "flow-note" }, fl.narrative) : null,
              f ? el("p", { class: "flow-rule" }, el("a", { href: `${siteBase}/rules/${f.id.toLowerCase()}/` }, f.id), ` · ${f.confidence} confidence`) : null),
            el("div", { class: "flow-frame corners" },
              el("div", { class: "pipe-ends", "aria-hidden": "true" }, el("span", {}, "Source"), el("span", {}, "Sink")),
              flowDiagram(fl, names)));
        })));
    }

    if (findings.length) parts.push(el("h3", { class: "report-h" }, "Findings"));
    const ref = targetRef(report);
    for (const sev of SEVERITIES) {
      const group = findings.filter((f) => f.severity === sev);
      if (!group.length) continue;
      parts.push(el("h4", { class: "sev-group" }, sevBadge(sev), plural(group.length, "finding")),
        ...group.map((f) => renderFinding(f, ref)));
    }

    parts.push(renderCoverage(report, meta));
    result.replaceChildren(...parts);
    result.hidden = false;
    result.querySelector("#result-title").focus();
  }

  // -- toxic-flow diagram ------------------------------------------------------------------
  const ROLE = {
    ingests_untrusted_content: "brings in untrusted content", reads_private_data: "reads private data",
    external_egress: "can send data out", destructive: "can delete or change things", code_exec: "can run code",
    persistence: "can persist changes",
  };
  const FIRST = ["ingests_untrusted_content"], LAST = ["external_egress", "destructive", "code_exec", "persistence"];

  function stepRole(labels, i, n) {
    const prefer = i === 0 ? FIRST : i === n - 1 ? LAST : ["reads_private_data"];
    const hit = prefer.find((l) => labels.includes(l)) || labels[0];
    return ROLE[hit] || hit || "";
  }

  // One box per step, arrows labelled with the agent session that connects them. Text only
  // via textContent (names come from scanned material). Stacks vertically on narrow screens.
  function flowDiagram(fl, names) {
    const NS = "http://www.w3.org/2000/svg";
    const steps = fl.nodes.map((id, i) => ({ id, name: names[id] || id, role: stepRole(fl.labels?.[id] || [], i, fl.nodes.length) }));
    const agent = String((fl.edges?.[0]?.[2]) || "").replace(/^agent:/, "") || "agent";
    const vertical = root.clientWidth < 620;   // the result box is hidden (0 px) while it is rebuilt
    const BW = 210, BH = 68, GAP = vertical ? 46 : 96;
    const n = steps.length;
    const w = vertical ? BW : n * BW + (n - 1) * GAP;
    const h = vertical ? n * BH + (n - 1) * GAP : BH;
    const svg = document.createElementNS(NS, "svg");
    svg.setAttribute("viewBox", `0 0 ${w} ${h}`);
    // Drawn at its own size so its text matches the page's; CSS only shrinks it to fit.
    svg.setAttribute("width", String(w));
    svg.setAttribute("height", String(h));
    svg.setAttribute("class", "flow-graph" + (vertical ? " vertical" : ""));
    svg.setAttribute("role", "img");
    svg.setAttribute("aria-label", steps.map((s) => `${s.name} (${s.role})`).join(", then via the agent, "));
    const node = (tag, attrs, text) => {
      const e = document.createElementNS(NS, tag);
      for (const [k, v] of Object.entries(attrs)) e.setAttribute(k, String(v));
      if (text !== undefined) e.textContent = text;
      return e;
    };
    const defs = node("defs", {});
    const marker = node("marker", { id: "flow-arrow", viewBox: "0 0 10 10", refX: 9, refY: 5, markerWidth: 7, markerHeight: 7, orient: "auto-start-reverse" });
    marker.append(node("path", { d: "M0,0 L10,5 L0,10 z", class: "flow-arrowhead" }));
    defs.append(marker);
    svg.append(defs);
    const clip = (t, max) => (t.length > max ? t.slice(0, max - 1) + "…" : t);
    steps.forEach((s, i) => {
      const x = vertical ? 0 : i * (BW + GAP), y = vertical ? i * (BH + GAP) : 0;
      const cls = i === 0 ? "source" : i === n - 1 ? "sink" : "middle";
      svg.append(node("rect", { x: x + 0.5, y: y + 0.5, width: BW - 1, height: BH - 1, rx: 3, class: `flow-box ${cls}` }));
      svg.append(node("text", { x: x + BW / 2, y: y + 29, class: "flow-name" }, clip(s.name, 24)));
      svg.append(node("text", { x: x + BW / 2, y: y + 49, class: `flow-role ${cls}` }, clip(s.role, 30)));
      if (i < n - 1) {
        const [x1, y1, x2, y2] = vertical ? [BW / 2, y + BH, BW / 2, y + BH + GAP] : [x + BW, BH / 2, x + BW + GAP, BH / 2];
        svg.append(node("line", { x1, y1, x2: vertical ? x2 : x2 - 2, y2: vertical ? y2 - 2 : y2, class: "flow-edge", "marker-end": "url(#flow-arrow)" }));
        const lx = vertical ? BW / 2 + 8 : (x1 + x2) / 2, ly = vertical ? (y1 + y2) / 2 + 4 : BH / 2 - 8;
        svg.append(node("text", { x: lx, y: ly, class: "flow-agent" + (vertical ? " side" : "") }, clip(agent, vertical ? 26 : 12)));
      }
    });
    return el("div", { class: "flow-wrap" }, svg);
  }

  // -- Agent Guard Web: rescans, badge, maintainer responses ---------------------------------------
  function unpinnedLink(t) {
    if (t.kind === "github") {
      const [owner, repo, ...sub] = t.locator.split("/");
      const base = `https://github.com/${owner}/${repo}`;
      return sub.length ? `${base}/tree/HEAD/${sub.join("/")}` : base;
    }
    if (t.kind === "npm") return `npm:${t.locator}`;
    if (t.kind === "pypi") return `pypi:${t.locator}`;
    return null;
  }

  function renderServerActions(report, meta, label) {
    const key = meta.serverKey;
    const t = targetRef(report);
    const box = el("div", { class: "server-actions" });
    const current = meta.server?.rule_pack;
    if (t.kind === "remote_mcp") {
      const again = el("button", { type: "button", class: "btn secondary small" }, "Check the server again");
      again.addEventListener("click", () => serverTask(`/api/reports/${key}/rescan`, {}, (final) => loadServerReport(final.report_key, label, final)));
      box.append(el("p", {}, again, el("span", { class: "muted small" }, " A recent check is reused for a few minutes.")));
    } else if (current && current.digest !== report.tool?.rule_pack_digest) {
      const rescan = el("button", { type: "button", class: "btn small" }, "Rescan this version with the current rules");
      rescan.addEventListener("click", () => serverTask(`/api/reports/${key}/rescan`, {}, (final) => loadServerReport(final.report_key, label, final)));
      box.append(el("p", {}, `This report used rule pack v${report.tool?.rule_pack}; the server now has v${current.version}. `, rescan));
    } else if (current) {
      box.append(el("p", { class: "muted small" }, "This report uses the server's current rules."));
    }
    const latest = unpinnedLink(t);
    if (latest) {
      const href = new URL(`${siteBase}/scan/`, location.href);
      href.searchParams.set("url", latest);
      box.append(el("p", { class: "small" }, "This report is pinned to one exact version. ", el("a", { href: href.href }, "Scan the latest version"), "."));
    }
    box.append(renderBadge(key), renderRespondHelp(report, key, label));
    return box;
  }

  function renderBadge(key) {
    const img = new URL(`${siteBase}/api/reports/${key}/badge.svg`, location.href).href;
    const page = new URL(`${siteBase}/scan/`, location.href);
    page.searchParams.set("report", key);
    const md = `[![Agent Guard](${img})](${page.href})`;
    const copy = el("button", { type: "button", class: "btn secondary small" }, "Copy Markdown");
    copy.addEventListener("click", () => navigator.clipboard?.writeText(md).then(() => { copy.textContent = "Copied"; }));
    return el("details", { class: "coverage" }, el("summary", {}, "README badge"),
      el("p", {}, el("img", { src: img, alt: "Agent Guard badge: finding counts for this report", height: "20" })),
      el("p", { class: "small muted" }, "The badge states the counts in this report for this exact version. It does not update when the project changes and never says \u201csafe\u201d."),
      el("pre", {}, el("code", {}, md)), copy);
  }

  function renderResponse(resp) {
    const file = `https://github.com/${resp.repository}/blob/${resp.commit}/${resp.path}`;
    return el("section", { class: "maintainer-response", "aria-labelledby": "maintainer-response-title" },
      el("h3", { id: "maintainer-response-title" }, "Maintainer response"),
      el("p", { class: "response-text" }, resp.text),
      el("p", { class: "muted small" }, "Published by committing ", el("a", { href: file }, resp.path), ` to github.com/${resp.repository} (commit `,
        el("code", {}, resp.commit.slice(0, 12)), "). Agent Guard checks where it came from, not what it says."));
  }

  function renderRespondHelp(report, key, label) {
    const kind = report.target?.kind;
    if (!["github", "npm", "pypi"].includes(kind)) return el("span", {});
    const check = el("button", { type: "button", class: "btn secondary small" }, "Check the repository");
    check.addEventListener("click", () => serverTask(`/api/reports/${key}/response`, {}, (final) =>
      loadServerReport(key, label, { notice: final.detail }), { keepResult: true }));
    const where = kind === "github" ? "the scanned repository" : `the GitHub repository named in the ${kind === "npm" ? "npm" : "PyPI"} package's metadata`;
    return el("details", { class: "coverage" }, el("summary", {}, "Maintainer? Respond to this report"),
      el("p", {}, `Commit a file named .agentguard/response.md to the default branch of ${where}. It must contain this line, and your response as plain text:`),
      el("pre", {}, el("code", {}, `report: ${key}\n\nYour response (up to 4,000 characters).`)),
      el("p", {}, "Then ask the server to read it. Anyone can view the response next to the report, with a link to the commit. To remove it, leave only the report line and check again."),
      check);
  }

  // Same text apart from case and a trailing period (a message that repeats the title).
  function same(a, b) { const n = (x) => String(x || "").trim().replace(/\.$/, "").toLowerCase(); return n(a) === n(b); }

  function fact(label, value, cls) { return el("div", { class: cls }, el("dt", {}, label), el("dd", {}, value)); }

  const LANE_TEXT = {
    block: "Counts on its own", evidence: "Counts when a second signal backs it", hunt: "Advisory (hunt lane)",
  };

  function renderFinding(f, ref) {
    const loc = locationUrl(ref, f.location);
    const maps = Object.entries(f.mappings || {}).flatMap(([fw, ids]) => (ids || []).map((id) => [fw, id]));
    const ev = f.evidence || {};
    const main = ev.snippet && f.location
      ? [{ location: { path: f.location.file, start_line: f.location.start?.line }, snippet: ev.snippet, hidden: (f.tags || []).includes("hidden") }]
      : ev.snippet ? [{ location: null, snippet: ev.snippet }] : [];
    const seen = new Set(main.map((e) => `${whereSpan(e.location)}|${e.snippet}`));
    const items = (ev.items || []).filter((e) => {
      const k = `${whereSpan(e.location)}|${e.snippet}`;
      if (!e.snippet || seen.has(k)) return false;
      seen.add(k);
      return true;
    }).slice(0, 6);
    const counted = f.category === "hygiene" ? "Informational" : f.corroborated === false ? "No: needs a second signal" : "Yes";
    const lane = `${f.lane}${(f.tags || []).includes("triage-agrees") ? " · the triage model agrees" : ""}`;
    const fix = f.fix || {};
    const title = f.variant ? `${f.id}/${f.variant}` : f.id;
    return el("details", { class: `finding ${f.severity}`, open: f.severity === "critical" || f.severity === "high" },
      el("summary", {}, sevBadge(f.severity), el("strong", {}, f.title), f.location ? el("span", { class: "loc" }, where(f.location)) : null),
      el("div", { class: "finding-body" },
        f.risk && !same(f.risk, f.title) ? el("p", { class: "finding-msg" }, f.risk) : null,
        el("dl", { class: "facts" },
          fact("Rule", [el("a", { href: `${siteBase}/rules/${f.id.toLowerCase()}/` }, title), el("span", { class: "muted" }, ` v${f.rule_version}`)]),
          fact("Category", f.category),
          fact("Lane", el("span", { title: LANE_TEXT[f.lane] || "" }, lane)),
          fact("Confidence", f.confidence),
          fact("Counts towards the verdict", counted),
          f.adjudication ? fact("Model review", `${f.adjudication.status} (${f.adjudication.model || "model"})`) : null,
          f.location ? fact("Location", loc ? el("a", { href: loc }, where(f.location)) : where(f.location), "wide") : null),
        main.length || items.length || ev.decoded ? el("div", {}, el("h4", {}, "Evidence"),
          ...main.map(renderEvidence),
          ev.decoded ? renderEvidence({ location: null, snippet: ev.decoded, hidden: true, decode_path: ev.derivation || [], detail: "decoded" }) : null,
          ...items.map(renderEvidence)) : null,
        (f.trace || []).length > 1 ? el("div", {}, el("h4", {}, "Trace"),
          el("ol", { class: "trace" }, ...f.trace.map((s) => el("li", {}, el("code", {}, `${s.file}:${s.line}`), s.role ? ` ${s.role}` : "",
            s.note ? el("span", { class: "muted" }, ` ${s.note}`) : null)))) : null,
        f.explanation || fix.summary ? el("div", { class: "advice" },
          f.explanation ? el("div", {}, el("h4", {}, "Why it matters"), el("p", {}, f.explanation)) : null,
          fix.summary ? el("div", { class: "fix" }, el("h4", {}, FIX_LABEL[fix.kind] || "How to fix"), el("p", {}, fix.summary)) : null) : null,
        maps.length ? el("p", { class: "maps" }, el("span", { class: "muted small" }, "Standards"),
          ...maps.map(([fw, id]) => el("span", { class: "pill" }, `${MAP_LABEL[fw] || fw} ${id}`))) : null,
        (f.references || []).length ? el("p", { class: "small" }, "References: ",
          ...f.references.filter(safeHref).flatMap((r, i) => [i ? ", " : "", el("a", { href: r }, r)])) : null));
  }

  function renderEvidence(ev) {
    return el("div", { class: "evidence" },
      el("p", { class: "ev-cap" },
        el("span", { class: "ev-dots", "aria-hidden": "true" }, el("i"), el("i"), el("i")),
        ev.location ? el("code", {}, whereSpan(ev.location)) : null,
        ev.hidden ? el("span", { class: "pill" }, "hidden content") : null,
        ev.decode_path?.length ? el("span", { class: "pill" }, `decoded: ${ev.decode_path.join(" → ")}`) : null,
        ev.detail ? el("span", {}, ev.detail) : null),
      ev.snippet ? el("pre", {}, el("code", {}, ev.snippet)) : null);
  }

  function renderCoverage(report, meta) {
    const cov = report.coverage || {};
    const skipped = (report.analyzers || []).filter((a) => a.status !== "ran");
    const events = report.stats?.limit_events || [];
    const items = [];
    if (meta.not_relevant) items.push(el("li", {}, `${meta.not_relevant} file(s) not fetched because no rule reads them (images, lockfiles and similar).`));
    for (const u of (cov.unanalysed || []).slice(0, 50)) items.push(el("li", {}, el("code", {}, u.path), ` could not be analysed: ${u.reason}`));
    if ((cov.excluded || []).length) {
      items.push(el("li", {}, "Not walked (dependency and version-control directories): ",
        ...cov.excluded.slice(0, 20).flatMap((d, i) => [i ? ", " : "", el("code", {}, d)])));
    }
    for (const a of skipped) items.push(el("li", {}, el("code", {}, a.id), ` ${a.status}: ${a.reason}`));
    for (const e of events.slice(0, 50)) items.push(el("li", {}, el("code", {}, e.kind), ` ${e.path}${e.detail ? " — " + e.detail : ""}`));
    if (events.length > 50) items.push(el("li", {}, `…and ${events.length - 50} more (see the JSON report).`));
    items.push(el("li", {}, "The scanned project's own .agentguard.yaml is ignored, so it cannot suppress its own findings."));
    return el("details", { class: "coverage" }, el("summary", {}, "What was not scanned"), el("ul", {}, ...items));
  }

  // Save to My scans: only when the user asks, and only the report (never the scanned files).
  function renderSave(report, meta, label) {
    const row = el("div", { class: "save-row" });
    const mine = `${siteBase}/account/`;
    if (meta.saved) {
      row.append(el("span", { class: "muted" }, "This report is saved to your account. "), el("a", { href: mine }, "My scans"));
      return row;
    }
    const entry = { report, label: label || meta.name || "", source: meta.serverKey ? "server" : "device", serverKey: meta.serverKey || null };
    const note = el("span", { class: "muted small" }, "Saves the report (verdict, findings and evidence snippets) to your account. Your files are not uploaded.");
    if (!account.user()) {
      const btn = el("a", { class: "btn secondary small", href: `${siteBase}/signin/?next=${encodeURIComponent(mine)}` }, "Sign in to save this report");
      // Keep the report for this tab so My scans can save it once sign-in finishes.
      btn.addEventListener("click", () => { account.setPendingSave(entry); });
      row.append(btn, note);
      return row;
    }
    const btn = el("button", { type: "button", class: "btn small" }, "Save to My scans");
    btn.addEventListener("click", async () => {
      btn.disabled = true;
      btn.textContent = "Saving…";
      try {
        const saved = await account.saveScan(entry);
        const view = new URL(`${siteBase}/scan/`, location.href);
        view.searchParams.set("saved", saved.id);
        row.replaceChildren(el("span", {}, "Saved. "), el("a", { href: mine }, "My scans"), " · ", el("a", { href: view.href }, "Link to this saved report"));
      } catch (err) {
        btn.disabled = false;
        btn.textContent = "Save to My scans";
        showError(err);
      }
    });
    row.append(btn, note);
    return row;
  }

  function renderDownloads(meta = {}, report = {}) {
    if (meta.saved) {
      // A saved report is downloaded as the JSON that was saved (the engine has not scanned it in this tab).
      const btn = el("button", { type: "button", class: "btn secondary small" }, "JSON");
      btn.addEventListener("click", () => {
        const url = URL.createObjectURL(new Blob([JSON.stringify(report, null, 2)], { type: "application/json" }));
        const a = el("a", {});
        a.href = url;
        a.download = "agentguard-report.json";
        document.body.append(a);
        a.click();
        a.remove();
        setTimeout(() => URL.revokeObjectURL(url), 10000);
      });
      return el("div", { class: "downloads" }, el("span", { class: "label" }, "Download"), btn);
    }
    const formats = [["json", "JSON", "application/json", "json"], ["sarif", "SARIF", "application/sarif+json", "sarif"],
      ["html", "HTML report", "text/html", "html"], ["markdown", "Markdown", "text/markdown", "md"], ["cyclonedx", "CycloneDX", "application/vnd.cyclonedx+json", "cdx.json"]];
    const row = el("div", { class: "downloads" }, el("span", { class: "label" }, "Download"));
    for (const [fmt, name, type, ext] of formats) {
      if (meta.serverKey) {
        const href = `${siteBase}/api/reports/${meta.serverKey}${fmt === "json" ? "" : `?format=${fmt}`}`;
        row.append(el("a", { class: "btn secondary small", href, download: `agentguard-report.${ext}` }, name), " ");
        continue;
      }
      const btn = el("button", { type: "button", class: "btn secondary small" }, name);
      btn.addEventListener("click", async () => {
        try {
          const res = await call({ type: "render", format: fmt });
          const url = URL.createObjectURL(new Blob([res.text], { type }));
          const a = el("a", {});
          a.href = url;
          a.download = `agentguard-report.${ext}`;
          document.body.append(a);
          a.click();
          a.remove();
          setTimeout(() => URL.revokeObjectURL(url), 10000);
        } catch (err) {
          showError(err);
        }
      });
      row.append(btn, " ");
    }
    return row;
  }
}
