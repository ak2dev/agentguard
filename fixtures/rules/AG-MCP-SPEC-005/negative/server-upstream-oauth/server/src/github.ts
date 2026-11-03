import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

// Users sign in with GitHub; this server is the OAuth client of GitHub, not of an MCP authorization server.
export function githubLoginUrl(clientId: string, redirectUri: string, challenge: string, state: string): string {
  const url = new URL("https://github.com/login/oauth/authorize");
  url.searchParams.set("client_id", clientId);
  url.searchParams.set("redirect_uri", redirectUri);
  url.searchParams.set("code_challenge", challenge);
  url.searchParams.set("code_challenge_method", "S256");
  url.searchParams.set("state", state);
  return url.toString();
}

export const server = new McpServer({ name: "demo", version: "0.1.0" });
