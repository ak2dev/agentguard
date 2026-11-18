---
name: reviewer
description: Reviews code changes.
mcpServers:
  db:
    command: npx
    args: ["-y", "@example/db-mcp@1.2.0"]
---
Review the diff and report problems.
