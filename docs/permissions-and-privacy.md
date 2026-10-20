# Permissions, privacy and retention

The default scanner has read-only access through the roots authorized by the operator. It makes no network calls, creates no project files, executes no source, and has no telemetry or LLM API integration. Installation downloads packages; `sources:check` is a separate, explicit maintainer network operation. These are distinct from scanning.

MCP results remain in memory, up to eight snapshots. Access expires after 30 minutes; expiry is checked on subsequent cache operations. Expired entries may remain allocated until the next operation or process exit. `juriscan_purge` immediately removes retained entries from the cache; process exit releases all state. No persistent scan database exists. Results already delivered to a host or redirected to a file cannot be revoked by purge.

Source buffers exist during scanning and are not retained as snapshots by the service. File paths, root metadata, hashes, findings and user-supplied fact responses may be sensitive. Results contain no source snippets, but report confidentiality is still the user's responsibility. The host may send tool results to a model provider or retain chat history. Juriscan does not control those practices.

Each stdio process is one trust context. Use separate processes for different clients/customers; do not expose it through a shared unauthenticated gateway. HTTP deployment and multi-tenant isolation are not shipped.

## Optional web-reference comparison

`juriscan_ip_web_compare` / `ip-web` is a separate opt-in network operation. It fetches only explicitly approved public references; local source/asset bytes and hashes are not uploaded. Publishers/proxies see the requested URL, user agent and connection metadata. Bodies are transient and never executed or copied into reports. The direct versus fixed-provider proxy trust boundaries, URL limits and unavailable-result behavior are documented in [IP review](intellectual-property.md). Offline scan guarantees do not claim this explicitly online operation makes no requests.
