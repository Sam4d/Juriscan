# Validation

`pnpm test` builds the binary then runs Vitest. It covers every detector with three positive, three negative and one ambiguous example; fixture behavior; legal-state/schema checks; industry combinations; filesystem confinement; symlink omission; resource limits; malformed source; cancellation; no source modification; redacted outputs; session eviction/expiry; deterministic fingerprints/prompts; scoped comparison; CLI exits; SARIF schema validation; and real stdio MCP sessions.

`pnpm smoke` repeats the two documented fixture commands and runs the vulnerable fixture under Node's permission model with filesystem writes/subprocesses denied and a guard that throws on common network APIs. No API keys are passed. This verifies exercised paths; it is not a formal proof of all dependency behavior or a substitute for an independent audit.

`pnpm check` adds strict type checking and local Markdown link/source-manifest checks. `pnpm format:check` checks formatting. `pnpm audit --prod` queries known package advisories at execution time; absence of advisories is not an independent security review.

The reference SDK tests do not claim vendor GUI testing. Synthetic fixtures and detector-level measurements cannot establish global vulnerability detection accuracy or legal accuracy. Exact observed release results are recorded in [validation](validation.md).
