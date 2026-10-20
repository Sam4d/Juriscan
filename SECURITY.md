# Security policy

This is an alpha release with no independent security audit. Only the current alpha is maintained; no response-time SLA is promised.

**Do not post exploitable details, real credentials, private code or personal information in public issues.** Private vulnerability reporting was observed disabled during release preparation; enabling it through the connected account returned HTTP 403. The repository owner needs to enable and verify this feature in GitHub settings. A Markdown policy cannot substitute for that permission.

If GitHub's “Report a vulnerability” option is available, use that private route. Otherwise open a public issue containing only a request for a private contact channel, without vulnerability details, and wait for the owner to supply one. No private email address or reporting service is invented here.

Report the version, affected interface, minimal synthetic reproduction, impact, environment, and mitigations privately. Do not test production systems or exfiltrate data to demonstrate a report. See the [threat model](docs/threat-model.md) for current boundaries and residual risks.
