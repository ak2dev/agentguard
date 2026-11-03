// Install commands pin the commit this site was built from, so they name code that
// exists and matches these docs, never a package name the project may not control.
// Vercel and GitHub Actions set the commit; local builds ask git.
import { execFileSync } from "node:child_process";

const SHA = /^[0-9a-f]{40}$/;

function buildCommit(): string {
  for (const value of [process.env.VERCEL_GIT_COMMIT_SHA, process.env.GITHUB_SHA]) {
    if (value && SHA.test(value)) return value;
  }
  try {
    const head = execFileSync("git", ["rev-parse", "HEAD"], { encoding: "utf8" }).trim();
    if (SHA.test(head)) return head;
  } catch {
    // no git: fall through to a placeholder rather than an unpinned command
  }
  return "<commit-sha>";
}

export const REPO_URL = "https://github.com/ak2dev/agentguard";
export const COMMIT = buildCommit();
export const SOURCE = `git+${REPO_URL}@${COMMIT}`;

/** A pip/pipx requirement for Agent Guard at the pinned commit, with optional extras. */
export const requirement = (extras?: string) => (extras ? `agentguard-v1[${extras}] @ ${SOURCE}` : SOURCE);
