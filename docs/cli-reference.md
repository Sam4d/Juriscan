# CLI reference

All commands use `node dist/cli.js` from the built checkout, or the `juriscan` executable from an installed local archive. `--help` and `--version` work without a project root.

| Command        | Inputs                                                                   | Result                                                  |
| -------------- | ------------------------------------------------------------------------ | ------------------------------------------------------- |
| `mcp`          | one or more `--allow-root PATH`                                          | stdio server; stdout reserved for protocol              |
| `scan`         | required `--root`, optional `--format`, `--fail-on`, `--max-files`       | fresh scan report                                       |
| `profile`      | required `--root`                                                        | observed domains and counts, not a full stack inventory |
| `plan`         | required `--root`                                                        | fresh scan and ordered remediation plan                 |
| `prompt`       | required `--root`                                                        | fresh scan and bounded remediation Markdown             |
| `intake`       | optional `--answers JSON`                                                | normalized known/unknown/disputed facts                 |
| `checklist`    | comma-separated `--industries`, `--jurisdictions`, optional `--features` | research recommendations and gaps                       |
| `rules`        | none                                                                     | technical detector metadata                             |
| `coverage`     | none                                                                     | legal research catalog                                  |
| `capabilities` | none                                                                     | implemented features and limitations                    |
| `doctor`       | none                                                                     | runtime/platform diagnostic                             |

Formats: `json`, `markdown`, `text` (Markdown-compatible text), `sarif`. Severity gates: `none` (default), `critical`, `high`, `medium`, `low`. Only `confirmed_technical` findings gate on severity. Heuristics do not. There is no generic compliance score.

Exit `0`: a complete scan without selected gating observations, or successful metadata command. Exit `1`: selected confirmed technical threshold reached. Exit `2`: invalid arguments/configuration/unsupported root. Exit `3`: partial or cancelled scan. Legal review is not implemented as an enforcement gate, so no pretend “legal verification failure” exit code is offered.

No implicit project config is loaded. CLI flags authorize and configure that command; MCP roots are configured only on process startup and limits are validated per request. No environment variables or secrets are required. Unsupported flags fail rather than being silently ignored by the argument parser; supported flags intended for other commands currently have no effect and should be omitted.

Default limits: 3,000 files, 500,000 bytes/file, 20 MB total, 30 seconds, 500 findings. MCP/core hard ceilings: 10,000 files, 1 MB/file, 50 MB total, 120 seconds, 2,000 findings. Traversal also limits entries to 20,000 and directory depth to 40. Common dependency/build directories are excluded. Unknown extensions are counted but outside coverage. Skipped supported files, symlinks, parsing failures, unsafe names and exhausted limits make scans partial.

The CLI is stateless: each scan/profile/plan/prompt invocation re-scans. Retained scan IDs and comparison are MCP/library features. CLI baseline files, interactive intake and suppression files are not implemented.

## IP commands

`ip-review --root PATH [--brands TermOne,TermTwo]` runs an offline license/asset/provenance review. `ip-web --root PATH --reference-url HTTPS_URL --allow-domain HOST --authorize-network` compares approved public references; repeat URL/domain flags for additional entries (up to 10). JSON results go to stdout. Exit 0 means the bounded review/comparison completed, not that rights are cleared; exit 3 means partial scope/unavailable references, and exit 2 means invalid authorization/inputs. [Full IP contract](intellectual-property.md).
