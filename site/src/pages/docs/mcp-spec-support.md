---
layout: ../../layouts/Doc.astro
title: MCP spec support
description: Which MCP specification versions and extensions each Agent Guard rule area covers.
---

# MCP spec support

Agent Guard reads MCP artifacts statically: client configs, tool manifests, `server.json`, server and client source code, and (with opt-in network flags) read-only metadata from remote servers. This page says which revisions of the [MCP specification](https://modelcontextprotocol.io/specification/2026-07-28) each rule area understands. Every requirement a rule cites was read in the specification itself; the sources and the dates they were checked are in `docs/sources.md`.

"Yes" means the area's checks apply to artifacts written for that revision. "Partly" means that revision requires some of what the area checks (the notes say which). "No" means the revision has the feature but none of these requirements; the rules still run and report what later revisions require. "—" means the revision has no such feature. Checks built from a newer revision's text (for example the 2026-07-28 `$ref` rules) also run on older artifacts when the risk is the same. "Reported" means Agent Guard records the server's revision and flags it as old instead of checking it.

<div class="table-scroll"><table class="matrix-table">
<thead><tr><th scope="col">Rule area</th><th scope="col">Rules</th><th scope="col">2024-11-05</th><th scope="col">2025-03-26</th><th scope="col">2025-06-18</th><th scope="col">2025-11-25</th><th scope="col">2026-07-28</th></tr></thead>
<tbody>
<tr><td>Client configuration</td><td><code>AG-MCP-CFG-*</code></td><td>Yes</td><td>Yes</td><td>Yes</td><td>Yes</td><td>Yes</td></tr>
<tr><td>Tool, prompt and resource text</td><td><code>AG-MCP-META-001</code>–<code>021</code></td><td>Yes</td><td>Yes</td><td>Yes</td><td>Yes</td><td>Yes</td></tr>
<tr><td>Tool schemas</td><td><code>AG-MCP-META-022</code>, <code>023</code></td><td>Yes</td><td>Yes</td><td>Yes</td><td>Yes</td><td>Yes</td></tr>
<tr><td>Output schemas</td><td><code>AG-MCP-META-024</code></td><td>—</td><td>—</td><td>Yes</td><td>Yes</td><td>Yes</td></tr>
<tr><td>MCP Apps views</td><td><code>AG-MCP-META-016</code>–<code>018</code>, <code>025</code>–<code>027</code></td><td>Yes</td><td>Yes</td><td>Yes</td><td>Yes</td><td>Yes</td></tr>
<tr><td>Tasks</td><td><code>AG-MCP-SPEC-001</code></td><td>—</td><td>—</td><td>—</td><td>Yes</td><td>Yes</td></tr>
<tr><td>Deprecated features</td><td><code>AG-MCP-SPEC-002</code></td><td>Yes</td><td>Yes</td><td>Yes</td><td>Yes</td><td>Yes</td></tr>
<tr><td>Client authorization code</td><td><code>AG-MCP-SPEC-003</code>–<code>005</code></td><td>—</td><td>No</td><td>Partly</td><td>Partly</td><td>Yes</td></tr>
<tr><td>Remote metadata and auth probes</td><td><code>AG-AUTH-*</code>, <code>--live-metadata</code></td><td>Reported</td><td>Reported</td><td>Yes</td><td>Yes</td><td>Yes</td></tr>
<tr><td>Server and script code</td><td><code>AG-CODE-*</code>, <code>AG-FLOW-*</code></td><td>Yes</td><td>Yes</td><td>Yes</td><td>Yes</td><td>Yes</td></tr>
</tbody>
</table></div>

## Notes by area

- **Client configuration.** Config files belong to each client, not to the specification, so these rules do not depend on the protocol revision. `AG-MCP-CFG-023` reports the HTTP+SSE transport, which 2025-03-26 replaced with Streamable HTTP and 2026-07-28 classifies as Deprecated.
- **Tool, prompt and resource text.** Tools, prompts and resources exist in every revision. Tool annotations (2025-03-26) and `title` fields (2025-06-18) are read when present; `AG-MCP-META-011` and `012` need annotations.
- **Tool schemas.** 2026-07-28 (SEP-2106) says implementations must not dereference a `$ref` that resolves to a network URI and should bound schema depth, subschema count or validation time. Schemas of every revision can carry the same `$ref` and the same exponential `$defs`, so the checks run on all of them. JSON Schema 2020-12 has been the default dialect since 2025-11-25; the checks read `$ref`, `$dynamicRef` and draft-2019-09 `$recursiveRef` alike. The depth and size bounds are Agent Guard's own; the specification gives no numbers.
- **Output schemas.** Structured tool output (`outputSchema`, `structuredContent`) arrived in 2025-06-18.
- **MCP Apps views.** MCP Apps is an official extension (`io.modelcontextprotocol/ui`, stable 2026-01-26), negotiated through extension capabilities, and its specification shows it on top of earlier core revisions, so the column is about the host and server, not the core revision. `AG-MCP-META-025`–`027` follow the 2026-01-26 extension text; `016`–`018` also read pre-extension `text/html` UI resources. Omitting `_meta.ui.csp` is not reported: hosts then apply a restrictive default.
- **Tasks.** 2025-11-25 added tasks as an experimental utility and required cryptographically secure task IDs wherever tasks are not bound to an authorization context; 2026-07-28 moved them into the Tasks extension (`io.modelcontextprotocol/tasks`), where unguessable IDs are required always.
- **Deprecated features.** Roots, Sampling and Logging are in every revision up to 2026-07-28, which deprecates them (SEP-2577; earliest removal in the first revision released on or after 2027-07-28). Their use is reported at info whatever revision the code targets; Sampling with `includeContext` "thisServer" or "allServers" (deprecated since 2025-11-25) at low.
- **Client authorization code.** 2024-11-05 had no authorization framework; 2025-03-26 added OAuth 2.1 without these requirements. The `resource` parameter (`AG-MCP-SPEC-005`, RFC 8707) is required from 2025-06-18; checking `iss` (`003`, RFC 9207) and binding stored client credentials to the issuer (`004`) are required from 2026-07-28. Only packages that use an MCP client outside their tests are checked, so a server that signs its users in to an upstream provider is not reported.
- **Remote probes.** `--live-metadata` and `--auth-checks` speak `server/discover` (2026-07-28) and the `initialize` handshake (2025-11-25, 2025-06-18). A server that offers only an older revision is reported by `AG-AUTH-010`. `AG-AUTH-006` (`iss` not advertised) and `AG-AUTH-007` (Dynamic Client Registration only) follow 2026-07-28.
- **Server and script code.** Taint from tool parameters to shells, `eval`, SQL, paths and outbound requests does not depend on the protocol revision.

## Extensions

| Extension | Version read | Rules |
|---|---|---|
| MCP Apps (`io.modelcontextprotocol/ui`) | 2026-01-26 (stable) | `AG-MCP-META-016`–`018`, `025`–`027` |
| Tasks (`io.modelcontextprotocol/tasks`) | 2026-07-28 | `AG-MCP-SPEC-001` |

The authorization extensions (OAuth client credentials, enterprise-managed authorization) and the Skills extension are not covered yet.
