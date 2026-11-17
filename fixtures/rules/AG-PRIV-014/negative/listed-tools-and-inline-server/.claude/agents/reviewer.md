---
name: reviewer
description: Reviews code changes.
tools: Read, Grep
mcpServers:
  db:
    command: npx
    args: ["-y", "@example/db-mcp@1.2.0"]
---
Review the diff and report problems.
