import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

const server = new McpServer({ name: "demo", version: "1.0.0" });

server.registerTool("add", { description: "Add two numbers.", inputSchema: { a: z.number(), b: z.number() } },
  async ({ a, b }) => ({ content: [{ type: "text", text: String(a + b) }] }));

import express from "express";
const app = express();
app.get("/health", (req, res) => {
  const token = req.query.access_token;
  res.json({ ok: Boolean(token) });
});
