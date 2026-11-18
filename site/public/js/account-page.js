// The /account/ page ("My scans"). Saved rows come from Supabase and were written from scan
// reports (scanned, possibly hostile, material), so they are inserted as text nodes only.
const account = window.agentguardAccount;
const $ = (id) => document.getElementById(id);
const base = document.documentElement.dataset.base || "";
if (account?.enabled) main();

function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === undefined || v === null || v === false) continue;
    if (k === "class") node.className = v;
    else node.setAttribute(k, String(v));
  }
  for (const c of children.flat()) if (c !== null && c !== undefined && c !== false) node.append(c instanceof Node ? c : String(c));
  return node;
}

const when = (iso) => {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? "" : d.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
};

async function main() {
  const status = $("account-status"), errorBox = $("account-error"), notice = $("account-notice");
  const showError = (msg) => { errorBox.textContent = msg || ""; errorBox.hidden = !msg; };

  const result = await account.ready;
  if (result?.error) showError(`Sign-in did not complete: ${result.error}`);

  $("account-signout").addEventListener("click", async () => {
    await account.signOut();
    location.reload();
  });

  const u = account.user();
  status.hidden = true;
  if (!u) {
    $("account-signedout").hidden = false;
    return;
  }
  $("account-who").textContent = `Signed in as ${u.email || u.name}`;
  $("account-who").hidden = false;
  $("account-actions").hidden = false;

  // A report the user asked to save before signing in.
  const pending = account.takePendingSave();
  if (pending?.report) {
    try {
      await account.saveScan(pending);
      notice.textContent = `Saved “${String(pending.label || "your report").slice(0, 120)}” to My scans.`;
      notice.hidden = false;
    } catch (e) {
      showError(`Could not save the report you scanned: ${e.message}`);
    }
  }
  await load();

  async function load() {
    status.textContent = "Loading your saved scans…";
    status.hidden = false;
    try {
      const rows = await account.listScans();
      $("account-empty").hidden = rows.length > 0;
      $("account-list").hidden = rows.length === 0;
      $("account-rows").replaceChildren(...rows.map(row));
    } catch (e) {
      if (e.signedOut) { location.reload(); return; }
      showError(e.message);
    } finally {
      status.hidden = true;
    }
  }

  function row(s) {
    const view = new URL(`${base}/scan/`, location.href);
    view.searchParams.set("saved", s.id);
    const del = el("button", { type: "button", class: "btn secondary small" }, "Delete");
    del.addEventListener("click", async () => {
      if (!confirm(`Delete the saved scan of “${String(s.label).slice(0, 80)}”? This cannot be undone.`)) return;
      del.disabled = true;
      try {
        await account.deleteScan(s.id);
        notice.textContent = "Deleted.";
        notice.hidden = false;
        await load();
      } catch (e) {
        showError(e.message);
        del.disabled = false;
      }
    });
    const verdict = ["ALLOW", "REVIEW", "BLOCK"].includes(s.verdict) ? s.verdict : "ALLOW";
    return el("tr", {},
      el("td", {}, el("time", { datetime: s.created_at }, when(s.created_at))),
      el("td", {}, el("a", { href: view.pathname + view.search }, s.label),
        s.source === "server" ? el("span", { class: "muted small" }, " · Agent Guard Web") : null),
      el("td", {}, el("span", { class: `verdict-pill ${verdict.toLowerCase()}` }, verdict),
        s.score !== null && s.score !== undefined ? el("span", { class: "muted small" }, ` score ${s.score}`) : null),
      el("td", {}, String(s.finding_count ?? 0)),
      el("td", {}, s.rule_pack ? `v${s.rule_pack}` : "—"),
      el("td", { class: "saved-actions" }, el("a", { class: "btn secondary small", href: view.pathname + view.search }, "View"), " ", del));
  }
}
