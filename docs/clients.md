# MCP client compatibility

The shipped interface is stdio. Tested: official `@modelcontextprotocol/client` **2.3.1**, with its default legacy negotiation and pinned **2026-07-28** negotiation. Both start the actual built CLI as a subprocess. Tests exercise discovery, calls, invalid arguments, resources, prompts and clean shutdown. This is reference-harness interoperability, not certification by a vendor.

Use a host's process launcher with executable `node` and arguments:

```json
[
  "/absolute/path/to/Juriscan/dist/cli.js",
  "mcp",
  "--allow-root",
  "/absolute/path/to/your/project"
]
```

Set the executable to an absolute Node 24 path if your GUI does not inherit the shell's PATH. Use absolute module/root paths because hosts may start in a different working directory. stdout belongs to MCP JSON messages; diagnostic errors use stderr. No service port or API key is needed.

Codex, Claude Code, Cursor, Gemini CLI, VS Code, Cline and Windsurf host-specific setup remains **not validated**. This document intentionally supplies the process invocation, not guessed configuration file locations. Consult the current official host documentation for its launcher schema and root permission model. To uninstall, remove that host's process entry and terminate its Juriscan process.

Troubleshooting: build `dist/cli.js`; use Linux and Node 24; explicitly set `--allow-root`; ensure tool `root` resolves inside it; re-scan expired/evicted IDs. A root error never means the client should request access to the whole filesystem. `juriscan_health` checks configured roots without disclosing credentials. HTTP/SSE/browser transports are not available.
