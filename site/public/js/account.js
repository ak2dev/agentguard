// Agent Guard accounts: Google sign-in through Supabase Auth (OAuth 2.0 authorization code
// with PKCE) and the signed-in user's saved scans, read and written through Supabase's REST
// API under row-level security (supabase/migrations/). Loaded only when the site was built
// with a Supabase project (src/data/auth.ts).
//
// Nothing is sent to Supabase until someone signs in: a signed-out visit only reads this
// browser's own storage. The session (access and refresh token, user id, email, name) is kept
// in localStorage, or in sessionStorage when "Keep me signed in" is unticked. No cookies.
const html = document.documentElement;
const SUPABASE = html.dataset.authUrl;
const KEY = html.dataset.authKey;
const BASE = html.dataset.base || "";
const SESSION = "agentguard.session";
const FLOW = "agentguard.signin";           // sessionStorage: PKCE verifier, return path, remember choice
const PENDING = "agentguard.pending-save";  // sessionStorage: a report to save once signed in
const AUTH_ERROR = "agentguard.signin-error";
const API_VERSION = { "X-Supabase-Api-Version": "2024-01-01" };
const COLS = "id,created_at,label,verdict,score,finding_count,rule_pack,engine,source,server_key";

// -- storage (every access can throw: private windows, blocked site data) ----------------------
function get(area, k) { try { return JSON.parse(area.getItem(k)); } catch { return null; } }
function put(area, k, v) { try { area.setItem(k, JSON.stringify(v)); return true; } catch { return false; } }
function drop(area, k) { try { area.removeItem(k); } catch { /* unavailable */ } }
const local = (() => { try { return window.localStorage; } catch { return null; } })();
const tab = (() => { try { return window.sessionStorage; } catch { return null; } })();
const areas = [local, tab].filter(Boolean);

function readSession() {
  for (const a of areas) {
    const s = get(a, SESSION);
    if (s && typeof s.access_token === "string" && typeof s.refresh_token === "string" && s.user?.id) return { ...s, area: a };
  }
  return null;
}

function writeSession(data, area) {
  const s = {
    access_token: data.access_token,
    refresh_token: data.refresh_token,
    expires_at: data.expires_at || Math.floor(Date.now() / 1000) + (data.expires_in || 3600),
    // Only what the pages show. The Google tokens Supabase returns once after sign-in are not kept.
    user: {
      id: data.user?.id,
      email: data.user?.email || "",
      name: data.user?.user_metadata?.full_name || data.user?.user_metadata?.name || "",
    },
  };
  for (const a of areas) if (a !== area) drop(a, SESSION);
  put(area || local || tab, SESSION, s);
  notify();
  return s;
}

function clearSession() {
  for (const a of areas) drop(a, SESSION);
  notify();
}

const listeners = new Set();
function notify() { const u = user(); for (const fn of listeners) fn(u); updateHeader(u); }
window.addEventListener("storage", (e) => { if (e.key === SESSION || e.key === null) notify(); });

// -- Supabase requests ----------------------------------------------------------------------------------
function problem(j, status) {
  const text = j && (j.msg || j.message || j.error_description || j.error);
  return { message: text ? String(text) : `Supabase returned HTTP ${status}.`, status };
}

async function authRequest(path, body, token) {
  let r;
  try {
    r = await fetch(`${SUPABASE}/auth/v1/${path}`, {
      method: "POST", credentials: "omit", cache: "no-store",
      headers: { apikey: KEY, "Content-Type": "application/json", ...API_VERSION, ...(token ? { Authorization: `Bearer ${token}` } : {}) },
      body: JSON.stringify(body || {}),
    });
  } catch {
    throw { message: "Could not reach the sign-in service. Check your connection and try again.", status: 0 };
  }
  const j = r.status === 204 ? {} : await r.json().catch(() => ({}));
  if (!r.ok) throw problem(j, r.status);
  return j;
}

let refreshing = null;
async function refresh(s) {
  const run = async () => {
    const now = readSession();   // another tab may have refreshed it already
    if (!now) return null;
    if (now.refresh_token !== s.refresh_token && now.expires_at - 60 > Date.now() / 1000) return now;
    try {
      return writeSession(await authRequest("token?grant_type=refresh_token", { refresh_token: now.refresh_token }), now.area);
    } catch (err) {
      if (err.status >= 400 && err.status < 500) clearSession();   // revoked or expired: signed out
      throw err;
    }
  };
  refreshing ??= (navigator.locks ? navigator.locks.request("agentguard-auth", run) : run()).finally(() => { refreshing = null; });
  return refreshing;
}

// A current access token, refreshed when it is about to expire; null when signed out.
async function accessToken() {
  const s = readSession();
  if (!s) return null;
  if (s.expires_at - 60 > Date.now() / 1000) return s.access_token;
  return (await refresh(s))?.access_token ?? null;
}

async function rest(method, query, body, prefer) {
  const token = await accessToken();
  if (!token) throw { message: "Sign in to see your saved scans.", status: 401, signedOut: true };
  let r;
  try {
    r = await fetch(`${SUPABASE}/rest/v1/saved_scans${query}`, {
      method, credentials: "omit", cache: "no-store",
      headers: { apikey: KEY, Authorization: `Bearer ${token}`, "Content-Type": "application/json", ...(prefer ? { Prefer: prefer } : {}) },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  } catch {
    throw { message: "Could not reach Supabase. Check your connection and try again.", status: 0 };
  }
  const j = r.status === 204 ? null : await r.json().catch(() => null);
  if (r.status === 401) { clearSession(); throw { message: "Your session has ended. Sign in again.", status: 401, signedOut: true }; }
  if (!r.ok) throw problem(j, r.status);
  return j;
}

// -- PKCE (RFC 7636) ---------------------------------------------------------------------------------------
function b64url(bytes) {
  return btoa(String.fromCharCode(...new Uint8Array(bytes))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function safeNext(next) {
  // Only a path on this site, never another origin (open redirect).
  try {
    const u = new URL(next || `${BASE}/account/`, location.origin);
    if (u.origin === location.origin && u.pathname.startsWith(`${BASE}/`)) return u.pathname + u.search;
  } catch { /* fall through */ }
  return `${BASE}/account/`;
}

async function signIn(provider = "google", { next, remember = true } = {}) {
  if (provider !== "google") throw { message: "Only Google sign-in is available for now." };
  if (!tab) throw { message: "Sign-in needs this site's storage, which the browser is blocking (private mode or blocked site data)." };
  const verifier = b64url(crypto.getRandomValues(new Uint8Array(48)));
  const challenge = b64url(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier)));
  put(tab, FLOW, { verifier, next: safeNext(next), remember: Boolean(remember), started: Date.now() });
  const q = new URLSearchParams({
    provider,
    redirect_to: new URL(`${BASE}/account/`, location.origin).href,
    code_challenge: challenge,
    code_challenge_method: "s256",
  });
  location.assign(`${SUPABASE}/auth/v1/authorize?${q}`);
}

// Finishes a sign-in when Supabase sends the browser back with ?code= (or an error).
async function finishSignIn() {
  const query = new URLSearchParams(location.search);
  const hash = new URLSearchParams(location.hash.replace(/^#/, ""));
  const pick = (k) => query.get(k) ?? hash.get(k);
  const code = pick("code"), error = pick("error_description") || pick("error");
  const flow = tab ? get(tab, FLOW) : null;
  if (!code && !error) return null;
  // Without a sign-in started in this tab, only the callback page treats ?code= as ours.
  if (!flow && (!code || location.pathname !== `${BASE}/account/`)) return null;
  // Remove the one-time code from the address bar and history before anything else.
  const clean = new URL(location.href);
  for (const k of ["code", "error", "error_code", "error_description", "state"]) clean.searchParams.delete(k);
  history.replaceState(null, "", clean.pathname + clean.search);
  if (tab) drop(tab, FLOW);
  let failure = null;
  if (error) failure = error.replace(/\+/g, " ");
  else if (!flow || Date.now() - flow.started > 15 * 60 * 1000) failure = "That sign-in link has expired or was started in another tab. Sign in again.";
  else {
    try {
      writeSession(await authRequest("token?grant_type=pkce", { auth_code: code, code_verifier: flow.verifier }), flow.remember ? local || tab : tab);
    } catch (err) {
      failure = err.message;
    }
  }
  if (failure) {
    if (tab) put(tab, AUTH_ERROR, failure);
    if (location.pathname !== `${BASE}/signin/`) location.replace(`${BASE}/signin/`);
    return { error: failure };
  }
  const next = flow.next || `${BASE}/account/`;
  if (next !== location.pathname + location.search) {
    location.replace(next);
    return new Promise(() => {});           // the page is going away
  }
  return { signedIn: true };
}

async function signOut() {
  const s = readSession();
  clearSession();
  // Revoke this session's refresh token on the server; signed out locally whatever happens.
  if (s) await authRequest("logout?scope=local", {}, s.access_token).catch(() => {});
}

// -- public API ------------------------------------------------------------------------------------------------
function user() { return readSession()?.user ?? null; }

function takeSignInError() {
  if (!tab) return null;
  const e = get(tab, AUTH_ERROR);
  drop(tab, AUTH_ERROR);
  return e;
}

const MAX_REPORT_CHARS = 1_500_000;

async function saveScan({ report, label, source = "device", serverKey = null }) {
  const json = JSON.stringify(report);
  if (json.length > MAX_REPORT_CHARS) throw { message: "This report is too large to save (over 1.5 MB). Download the JSON instead." };
  const findings = (report.findings || []).filter((f) => !f.suppressed);
  const verdict = ["ALLOW", "REVIEW", "BLOCK"].includes(report.verdict) ? report.verdict : "ALLOW";
  const score = Number.isInteger(report.score) ? Math.max(0, Math.min(100, report.score)) : null;
  const rows = await rest("POST", `?select=${COLS}`, {
    label: String(label || report.target?.ref?.locator || "Scan").slice(0, 2048),
    verdict, score,
    finding_count: findings.length,
    rule_pack: report.tool?.rule_pack ? String(report.tool.rule_pack).slice(0, 64) : null,
    engine: report.tool?.version ? String(report.tool.version).slice(0, 64) : null,
    source: source === "server" ? "server" : "device",
    server_key: serverKey && /^[0-9a-f]{32}$/.test(serverKey) ? serverKey : null,
    report,
  }, "return=representation");
  return rows?.[0] ?? null;
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

const api = Object.freeze({
  enabled: Boolean(SUPABASE && KEY),
  user,
  onChange(fn) { listeners.add(fn); return () => listeners.delete(fn); },
  signIn, signOut, takeSignInError,
  saveScan,
  listScans: () => rest("GET", `?select=${COLS}&order=created_at.desc&limit=200`),
  async getScan(id) {
    if (!UUID.test(id)) throw { message: "That saved scan link is not valid." };
    const rows = await rest("GET", `?select=${COLS},report&id=eq.${id}`);
    if (!rows?.length) throw { message: "That saved scan does not exist, or it belongs to another account." };
    return rows[0];
  },
  async deleteScan(id) {
    if (!UUID.test(id)) throw { message: "That saved scan id is not valid." };
    await rest("DELETE", `?id=eq.${id}`, undefined, "return=minimal");
  },
  // A report the user asked to save before signing in; saved by the My scans page afterwards.
  setPendingSave(data) { return tab ? put(tab, PENDING, data) : false; },
  takePendingSave() { if (!tab) return null; const d = get(tab, PENDING); drop(tab, PENDING); return d; },
});

// -- header: "Sign in" or "My scans" ---------------------------------------------------------------------
// Toggles data-off (visibility, not display) so the header keeps its geometry.
function updateHeader(u) {
  for (const a of document.querySelectorAll("[data-account-signin]")) a.toggleAttribute("data-off", Boolean(u));
  for (const a of document.querySelectorAll("[data-account-mine]")) {
    a.toggleAttribute("data-off", !u);
    if (u) a.title = `Signed in as ${u.email || u.name}`;
  }
}

const ready = SUPABASE && KEY ? finishSignIn().catch((err) => ({ error: err.message })) : Promise.resolve(null);
window.agentguardAccount = Object.freeze({ ...api, ready });
updateHeader(user());
