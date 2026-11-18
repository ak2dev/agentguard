// Sign-in (Supabase Auth, Google) and "My scans". Off unless both values are set at build time:
//   PUBLIC_SUPABASE_URL              https://<project-ref>.supabase.co          (or SUPABASE_URL)
//   PUBLIC_SUPABASE_PUBLISHABLE_KEY  the publishable key (sb_publishable_…)      (or SUPABASE_KEY;
//                                    the legacy anon key also works)
// Both end up in every page, so they must be the public values. The build refuses a secret or
// service-role key, whatever the variable is called: those bypass row-level security and must
// never reach a browser. This module runs only at build time, so process.env is the build's environment.
const pick = (...values: (string | undefined)[]) => (values.find((v) => v && v.trim()) ?? "").trim();
const url = pick(
  import.meta.env.PUBLIC_SUPABASE_URL, process.env.PUBLIC_SUPABASE_URL,
  import.meta.env.SUPABASE_URL, process.env.SUPABASE_URL,
).replace(/\/+$/, "");
const key = pick(
  import.meta.env.PUBLIC_SUPABASE_PUBLISHABLE_KEY, process.env.PUBLIC_SUPABASE_PUBLISHABLE_KEY,
  import.meta.env.PUBLIC_SUPABASE_ANON_KEY, process.env.PUBLIC_SUPABASE_ANON_KEY,
  import.meta.env.SUPABASE_KEY, process.env.SUPABASE_KEY,
);

function jwtRole(token: string): string | null {
  const part = token.split(".")[1];
  if (!part) return null;
  try {
    return JSON.parse(Buffer.from(part.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8")).role ?? null;
  } catch {
    return null;
  }
}

if (url || key) {
  if (!url || !key) throw new Error("Set both the Supabase URL (PUBLIC_SUPABASE_URL or SUPABASE_URL) and its publishable key (PUBLIC_SUPABASE_PUBLISHABLE_KEY or SUPABASE_KEY), or neither.");
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw new Error(`PUBLIC_SUPABASE_URL is not a URL: ${url}`);
  }
  if (parsed.protocol !== "https:" || parsed.pathname !== "/" || parsed.search || parsed.hash) {
    throw new Error("PUBLIC_SUPABASE_URL must be the project's https:// origin, e.g. https://abcd1234.supabase.co");
  }
  if (key.startsWith("sb_secret_") || jwtRole(key) === "service_role") {
    throw new Error("The Supabase key set for the site is a secret key. Use the publishable (or anon) key; never ship a secret key to the browser.");
  }
}

export const auth = {
  enabled: Boolean(url && key),
  url,
  key,
  origin: url ? new URL(url).origin : "",
};
