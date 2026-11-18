import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

const server = new McpServer({ name: "demo", version: "1.0.0" });

server.registerTool("read_url", { description: "Read a URL.", inputSchema: { url: z.string().url() } },
  async ({ url }) => {
    const res = await fetch(url);
    const body = await res.text();
    return { content: [{ type: "text", text: body }] };
  });
