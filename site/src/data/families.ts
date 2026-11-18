// The 23 rule families of the catalogue (spec/rules.md), in the order the specification lists them, with a short
// label for charts and menus. POL (policy outcomes) is an extension family: it reports what a policy decided.
export const FAMILY_ORDER = [
  "INJ", "OBF", "MM", "EXF", "CRED", "EXEC", "PERSIST", "IMPACT", "MANIP", "PRIV", "CFG", "PLUG", "MCP", "VULN",
  "SUPPLY", "META", "FLOW", "CI", "WS", "IMG", "CONN", "EVADE", "HYG", "POL",
] as const;

export const FAMILY_SHORT: Record<string, string> = {
  INJ: "Injection and hijack", OBF: "Hidden content", MM: "Media and documents", EXF: "Exfiltration",
  CRED: "Credentials", EXEC: "Execution", PERSIST: "Persistence", IMPACT: "Destructive action",
  MANIP: "Output manipulation", PRIV: "Over-privilege", CFG: "Agent settings and hooks", PLUG: "Plugins and marketplaces",
  MCP: "MCP servers", VULN: "Implementation flaws", SUPPLY: "Supply chain", META: "Metadata and identity",
  FLOW: "Toxic flows", CI: "Agentic CI", WS: "Workspace auto-execution", IMG: "Container images",
  CONN: "Remote connectors", EVADE: "Evasion and coverage", HYG: "Hygiene", POL: "Policy outcomes",
};

export const LANE_TEXT: Record<string, string> = {
  block: "decides a verdict on its own",
  evidence: "counts when a second signal backs it",
  hunt: "advisory; reported when the policy turns the hunt lane on",
};

export const FIX_TEXT: Record<string, string> = {
  auto: "Safe auto-fix", patch: "Drafted patch, kept only after a re-scan", guidance: "Guidance", remove: "Do not install",
  none: "No fix",
};

type Family = { family: string; name: string; about: string; rules: number; implemented: number };

/** The families of the generated catalogue in specification order (unknown ones last). */
export function orderedFamilies(families: Family[]): Family[] {
  const rank = (f: string) => {
    const i = (FAMILY_ORDER as readonly string[]).indexOf(f);
    return i < 0 ? FAMILY_ORDER.length : i;
  };
  return [...families].sort((a, b) => rank(a.family) - rank(b.family) || a.family.localeCompare(b.family));
}
