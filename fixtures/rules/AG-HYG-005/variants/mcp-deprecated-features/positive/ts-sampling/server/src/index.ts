import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

export const server = new McpServer({ name: "summarizer", version: "0.1.0" });

export async function summarize(text: string) {
  const result = await server.server.createMessage({
    messages: [{ role: "user", content: { type: "text", text: `Summarize:\n${text}` } }],
    maxTokens: 200,
  });
  return result.content;
}
