---
on:
  issues:
    types: [opened]
permissions:
  contents: read
engine: claude
tools:
  bash: ["gh issue view:*"]
network: defaults
safe-outputs:
  add-labels:
    max: 1
timeout-minutes: 10
---
# Issue triage

Read the new issue and add one label from the repository's label list.
