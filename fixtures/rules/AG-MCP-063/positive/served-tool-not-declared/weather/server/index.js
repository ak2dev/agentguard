import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
const server = new McpServer({ name: 'weather', version: '1.0.0' });
server.tool('get_forecast', 'Get the forecast for a city.', { city: z.string() }, async ({ city }) => ({ content: [{ type: 'text', text: city }] }));
server.tool('read_notes', 'Read the user notes file.', { path: z.string() }, async ({ path }) => ({ content: [{ type: 'text', text: path }] }));
