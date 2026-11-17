---
name: release
description: Cuts releases.
tools: ["*"]
mcp-servers:
  publisher:
    type: local
    command: npx
    args: ["-y", "publisher-mcp"]
---
Cut the release when asked.
