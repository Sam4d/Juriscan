# Release gates and roadmap

## Shipped in 0.1.0-alpha.1

Twelve pattern detectors with positive/negative/ambiguous fixtures; read-only bounded Linux scanning; legacy/current stdio MCP interoperability; 25 tools; four resources plus a scan-summary template; four review prompts; legal intake; 201 unverified research entries; industry/feature checklist composition; remediation prompts; static comparison; JSON/Markdown/SARIF; CLI and CI checks.

## Required before calling this a supported production v1

- Independent security review, expanded adversarial/parser/race testing and Windows/macOS boundary implementations if support is advertised.
- Jurisdiction-qualified review of each active legal binding, exact source versions, commencement/litigation status, applicability tests and update policy. Zero bindings are active now.
- Real host-client installation verification beyond the SDK harness.
- Enable and verify a private security-reporting route as repository owner; the connected account received HTTP 403 when attempting this setting change. Define response ownership before production support.
- More representative evaluation across real stacks; runtime access-control, webhook and accessibility tests in authorized synthetic environments.
- Release provenance/SBOM, signed artifacts and an approved package publication process. No npm package has been published.

## Starter-spec differences retained explicitly

| Starter area                 | Current alpha                                             | Work remaining                                                   |
| ---------------------------- | --------------------------------------------------------- | ---------------------------------------------------------------- |
| D01 secrets                  | Literal/provider patterns and client privilege references | Broader entropy/context handling, history/bundle adapters        |
| D02 Supabase/Postgres        | Disabled RLS and unconditional-policy patterns            | Missing-RLS reasoning and migration-order/schema/grant semantics |
| D03 Firebase                 | Literal unconditional permissions                         | Ownership reasoning, nesting semantics and emulator integration  |
| D04 cross-user authorization | Deferred                                                  | Framework/ORM flow analysis and real negative tests              |
| D05 sensitive logging        | Direct console identifier/property inspection             | Alias/taint analysis and telemetry adapters                      |
| D06 tracking                 | Static discovery                                          | Authorized browser before/after-choice verification              |
| D07 deletion                 | Local-only deletion indicator                             | Store/processor correlation, retention/backup evaluation         |
| D08 notice versus behavior   | Deferred                                                  | Policy statement extraction and evidence-grounded comparison     |
| D09 billing                  | Function-local Stripe event/signature heuristic           | Idempotency, recurring disclosures, refund/cancellation review   |
| D10 accessibility            | JSX alt/label/opener hardening                            | Rendered keyboard/contrast/ARIA and assistive-technology tests   |

Further backlog: data-flow graph (not faked by an empty tool), background jobs and dedicated scan-cancellation tools (request cancellation works today), broader language adapters, granular finding resources, per-finding fix prompts, signed rulepack updates, suppression/baseline workflow, HTTP transport with reviewed authentication, user-authorized browser audits, plugin sandboxing, real-world legal/technical benchmark datasets, the complete [supplied research inventory](supplied-research-backlog.md), sector authorities and local law coverage.

No target date or coverage percentage converts an open item into an implemented feature. Public GitHub availability is not production legal readiness.

## Copyright/IP additions

Shipped: offline SPDX/package-license and root-license-family review; notice discovery; asset provenance declarations; selected brand-term references; manual ownership/trademark/patent/trade-dress review guidance; opt-in public-reference exact-byte and sampled-text matching with network safeguards. Legal status remains not assessed.

Still unimplemented: whole-web discovery/search indexes, reverse-image/audio/logo similarity, trademark/patent register automation, transitive license resolution/compatibility proof, ownership verification, fair-use decisions, legally reviewed infringement opinions and complete web coverage. These are not hidden behind a claim that the new tools scan everything.
