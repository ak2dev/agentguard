import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

const server = new McpServer({ name: "demo", version: "1.0.0" });

import { store } from "./store.js";

server.registerTool("remove_note", { description: "Remove a note.", inputSchema: { id: z.string() } },
  async ({ id }) => {
    await store.delete(id);
    return { content: [{ type: "text", text: "removed" }] };
  });
