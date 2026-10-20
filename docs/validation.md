# Release validation

Validation is for the current Linux cloud checkout and source preview, not an independent audit or proof of worldwide law coverage. See [testing](testing.md) for commands and scope.

- Node 24.19.0; pnpm 12.14.0; TypeScript 6.0.3; MCP server/client 2.3.1.
- Strict build, detector/security/legal/report/CLI tests, and real reference-SDK stdio sessions are exercised by `pnpm check`.
- The protocol harness covers default legacy negotiation and pinned 2026-07-28 negotiation. Individual GUI/client vendors remain untested.
- Vulnerable fixture: 12 observations. Negative fixture: zero observations. All legal status remains not assessed.
- Guarded read-only/offline scan passes with no API keys, no filesystem writes, no child processes, and network APIs blocked by the validation guard.
- SARIF 2.1.0 and finding JSON schemas validate. Local documentation links and generated tool inventory are checked.
- Production dependency audit during implementation reported zero known advisories. This does not prove dependencies are vulnerability-free.
- Official legal-source retrieval outcomes are recorded separately. No legally qualified review, complete legal-text/current-law proofcheck, or reviewed jurisdictional rulepack exists.
- A GitHub push and committed workflow do not prove a remote CI run or npm publication. Neither is claimed until observed separately.

The implementation run passed 177 tests across eight test files. A packed archive was installed into an isolated directory and its CLI successfully scanned the negative fixture. Tests should be rerun for subsequent source/dependency changes; these statements do not certify future commits.

Copyright/IP validation additionally covers SPDX expressions/alternatives/exceptions, license-text disagreement, bounded provenance review, brand/notice observations, exact/text reference matching, private-address and redirect rejection, response limits, TLS-hostname/DNS pinning, and curated-proxy selection. A live approved-provider fetch completed and found the expected shared Apache license text as a human-review match. No whole-web search, visual similarity or infringement determination was performed.

GitHub private vulnerability reporting was observed disabled. The connected account received HTTP 403 when attempting to enable it; the owner must enable and verify a private reporting route. No enabled reporting service is claimed.
