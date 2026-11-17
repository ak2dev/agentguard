---
on:
  issues:
    types: [opened]
permissions:
  contents: read
engine: claude
tools:
  bash: ["*"]
timeout-minutes: 10
---
# Issue triage

Read the new issue and add one label from the repository's label list.
