# MCP tools, resources and prompts

Generated from discovery of the built server. Full exact input schemas are in [mcp-tool-schemas.json](mcp-tool-schemas.json). Tool responses contain JSON text plus structured content. Errors use `isError: true` and safe code/message fields. SDK schema validation handles invalid requests; core errors include ROOT_DENIED, INVALID_RULE, NOT_FOUND, BUSY, OUTPUT_LIMIT and PROJECT_MISMATCH.

Roots are set by the process operator, not a tool. Outputs are limited to 1 MB; findings and catalogs paginate with `offset`, `limit` (1–100), and `next_offset`. Scan tools finish within the request. Cancel using MCP request cancellation; no fake background job/cancellation tool is advertised. Scan status retrieves completed/partial/cancelled retained results.

| Tool | Purpose |
| ---- | ------- |

| `juriscan_version` | Build and schema versions; no remote update lookup. |

| `juriscan_capabilities` | Actual technical coverage and explicit limitations. |

| `juriscan_health` | Check authorized roots are available without exposing credentials. |

| `juriscan_scan` | Read-only bounded scan of an explicitly allowed root. Request cancellation is supported by MCP. |

| `juriscan_project_profile` | Scan supported files and summarize observed domains. This is not a complete dependency or data-flow inventory. |

| `juriscan_scan_status` | Retrieve a retained completed, partial or cancelled scan status. |

| `juriscan_findings` | Paginated observations; no source excerpts or credential values. |

| `juriscan_get_finding` | Retrieve one evidence-backed observation. |

| `juriscan_legal_intake` | Normalize user facts and surface missing facts; no invented answers. |

| `juriscan_applicability` | Research candidates only. No legal rule is verified or asserted applicable. |

| `juriscan_list_jurisdictions` | Paginated catalog jurisdictions; all legal obligations remain unverified. |

| `juriscan_list_rules` | Paginated active technical detectors. Legal research is in the legal catalog. |

| `juriscan_get_rule` | Technical detector metadata, acceptance tests, source pointers and limitations. |

| `juriscan_legal_catalog` | Filter the research inventory, including missing primary sources. Not a statement of current law. |

| `juriscan_industry_taxonomy` | Available sectors, product archetypes and feature dimensions. |

| `juriscan_industry_checklist` | Compose sector/feature/market research questions. Uncovered combinations remain visible. |

| `juriscan_remediation_plan` | Prioritized tasks, acceptance tests and human approval gates. |

| `juriscan_generate_master_prompt` | Deterministic bounded implementation prompt, without copying source instructions. |

| `juriscan_compare` | Compare static observations within the same project and scan scope. |

| `juriscan_verify` | Re-scan and compare; does not execute project tests or claim legal remediation. |

| `juriscan_report` | Return JSON, Markdown, text or SARIF in the response; never writes a file. |

| `juriscan_rulepack_status` | Offline legal and technical freshness disclosure. |

| `juriscan_purge` | Discard this session’s in-memory scans. |

| `juriscan_ip_review` | Offline copyright/license/asset provenance and selected brand-term review. No ownership or infringement determination. |

| `juriscan_ip_web_compare` | Explicitly authorized public-reference GET and local byte/text comparison. No upload, search engine, crawling, or infringement conclusion. Requires exact approved domains and authorized_network true. |

## Resources

Static resources: `juriscan://schema/finding/v1`, `juriscan://schema/legal/v1`, `juriscan://coverage/current`, `juriscan://rulepacks/technical-global/manifest`. Dynamic resource: `juriscan://scans/{scan_id}/summary`. All are process-local JSON; summaries omit full finding lists. No global public source-code resource exists.

## Prompts

`juriscan_prelaunch_review`, `juriscan_privacy_review`, `juriscan_child_safety_review` and `juriscan_subscription_review` guide scoped review. They do not execute scans or modifications on their own. Generated remediation prompts use `juriscan_generate_master_prompt` with a retained `scan_id`; no separate persistent plan store exists.

## Lifetime

Up to eight snapshots per process. Expiry is checked on cache operations after 30 minutes; purge clears the cache. Re-scan expired IDs. Only one scan may execute at once; concurrent requests receive BUSY. [Privacy details](permissions-and-privacy.md).
