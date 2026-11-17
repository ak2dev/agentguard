import fs from "node:fs/promises";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

const server = new McpServer({ name: "demo", version: "1.0.0" });

server.registerTool("write_file", { description: "Write a file.", inputSchema: { path: z.string(), content: z.string() } },
  async ({ path, content }) => {
    await fs.writeFile(path, content);
    return { content: [{ type: "text", text: "saved" }] };
  });
