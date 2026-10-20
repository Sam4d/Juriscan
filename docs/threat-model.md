# Threat model

Assets include confidential project code, credentials, sensitive path names, finding metadata, the MCP host's instruction boundary, and user trust in legal claims. Attackers can control repository contents and filenames, directories that change during scanning, oversized inputs, and tool arguments. The operator chooses allowed roots outside project-controlled configuration.

| Threat                     | Control                                                                                          | Remaining limitation                                                                                                    |
| -------------------------- | ------------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------- |
| Traversal / symlink escape | Canonical allowed roots, no-follow file opens, Linux descriptor target validation before reading | Hard links and bind mounts already inside an authorized root belong to that root; don't authorize hostile shared mounts |
| File replacement race      | Opened descriptor is pinned and checked before bounded reads                                     | A concurrently modified file can yield mixed contents; scan a quiescent checkout for reproducibility                    |
| Untrusted code execution   | Parser-only reads; no package scripts, dynamic imports or subprocesses in the engine             | Dependency compromise and parser bugs remain possible                                                                   |
| Secret leakage             | No source excerpts; known credential shapes are detected without emitting values                 | Paths and hashes are metadata; protect reports and host conversations; no universal secret classifier exists            |
| Prompt injection           | Repository text never copied into generated prompts; paths are quoted and labeled untrusted      | No string-formatting defense can guarantee a model host ignores all malicious data                                      |
| Resource exhaustion        | Files, bytes, findings, duration, entries, depth, cache and concurrent scans bounded             | Parser work for one bounded file is synchronous; cancellation/timeout is cooperative between operations                 |
| False legal assurance      | No active legal rules, no overall compliance score, explicit source/review gaps                  | Users must not interpret a research catalog or clean scan as clearance                                                  |
| Session disclosure         | One local stdio process, bounded memory, no multi-tenant HTTP                                    | Anyone controlling that process/host can read its results                                                               |
| Poisoned source update     | Explicit separate retrieval; metadata never promotes rules to verified                           | Review redirects, publisher identity, licensing, legal version and court status manually                                |

Run `pnpm smoke` to exercise the offline guard and Node's denied filesystem-write/subprocess permissions. Security tests cover outside roots, symlinks, resource limits, cancellation, malicious comments, redaction and cache eviction. This is tested hardening, not an independent security audit. OS sandboxing is recommended when handling hostile repositories.

## IP and reference-review additions

Offline IP inspection shares the canonical-root, no-follow descriptor, bounded-read and no-execution model. SPDX expressions are parsed with a pinned parser, with length limits; arbitrary package values are not echoed. Provenance declarations are untrusted claims and never cause linked files or URLs to be opened. Issue output is capped; omissions remain visible.

Opt-in reference comparisons introduce external content and network metadata. Arbitrary approved domains use validated public IPv4 and pinned connections; fixed public providers can use a trusted operator proxy. This proxy path relies on its DNS/egress policy and is reported separately. Query strings, credentials, redirects, compressed responses, private addresses and unapproved domains are denied. Byte/time limits apply, source content is not sent, and remote scripts/links are not executed. Similarity is never a legal verdict. See [IP review](intellectual-property.md).
