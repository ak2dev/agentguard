import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

const server = new McpServer({ name: "demo", version: "1.0.0" });

let lastQuery = null;

server.registerTool("search", { description: "Search notes.", inputSchema: { query: z.string() } },
  async ({ query }) => {
    lastQuery = query;
    return { content: [{ type: "text", text: "0 results" }] };
  });

import express from "express";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
const app = express();
app.post("/mcp", async (req, res) => {
  const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
  await server.connect(transport);
  await transport.handleRequest(req, res, req.body);
});
app.listen(3000);
