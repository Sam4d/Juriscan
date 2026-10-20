import { writeFile, readFile } from "node:fs/promises";
import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { RULES } from "../dist/rules.js";
import { CATALOG, INDUSTRIES, FEATURES, ARCHETYPES } from "../dist/legal.js";
import path from "node:path";
const client = new Client({
  name: "juriscan-doc-generation",
  version: "1.0.0",
});
try {
  await client.connect(
    new StdioClientTransport({
      command: process.execPath,
      args: [
        "dist/cli.js",
        "mcp",
        "--allow-root",
        path.resolve("fixtures/vulnerable"),
      ],
      stderr: "pipe",
    }),
  );
  const { tools } = await client.listTools();
  await writeFile(
    "docs/mcp-tool-schemas.json",
    JSON.stringify(tools, null, 2) + "\n",
  );
  const text = [
    "# MCP tools, resources and prompts",
    "Generated from discovery of the built server. Full exact input schemas are in [mcp-tool-schemas.json](mcp-tool-schemas.json). Tool responses contain JSON text plus structured content. Errors use `isError: true` and safe code/message fields. SDK schema validation handles invalid requests; core errors include ROOT_DENIED, INVALID_RULE, NOT_FOUND, BUSY, OUTPUT_LIMIT and PROJECT_MISMATCH.",
    "Roots are set by the process operator, not a tool. Outputs are limited to 1 MB; findings and catalogs paginate with `offset`, `limit` (1–100), and `next_offset`. Scan tools finish within the request. Cancel using MCP request cancellation; no fake background job/cancellation tool is advertised. Scan status retrieves completed/partial/cancelled retained results.",
    "| Tool | Purpose |\n| --- | --- |",
    ...tools.map(
      (t) => `| \`${t.name}\` | ${t.description.replaceAll("|", "/")} |`,
    ),
    "## Resources",
    "Static resources: `juriscan://schema/finding/v1`, `juriscan://schema/legal/v1`, `juriscan://coverage/current`, `juriscan://rulepacks/technical-global/manifest`. Dynamic resource: `juriscan://scans/{scan_id}/summary`. All are process-local JSON; summaries omit full finding lists. No global public source-code resource exists.",
    "## Prompts",
    "`juriscan_prelaunch_review`, `juriscan_privacy_review`, `juriscan_child_safety_review` and `juriscan_subscription_review` guide scoped review. They do not execute scans or modifications on their own. Generated remediation prompts use `juriscan_generate_master_prompt` with a retained `scan_id`; no separate persistent plan store exists.",
    "## Lifetime",
    "Up to eight snapshots per process. Expiry is checked on cache operations after 30 minutes; purge clears the cache. Re-scan expired IDs. Only one scan may execute at once; concurrent requests receive BUSY. [Privacy details](permissions-and-privacy.md).",
  ];
  await writeFile("docs/mcp-tools.md", text.join("\n\n") + "\n");
} finally {
  await client.close();
}
await writeFile(
  "docs/detectors.md",
  [
    "# Detector contracts",
    "Generated from shipped rule metadata. `confirmed_technical` confirms the syntactic condition only. All legal applicability is not assessed. Each detector has three positive, three negative and one ambiguous case in test/detectors.test.ts. These examples are a controlled test set, not real-world accuracy guarantees.",
    ...RULES.map(
      (r) =>
        `## ${r.id}\n\n${r.title}. Classification: ${r.classification}; severity: ${r.severity}; confidence: ${r.confidence}.\n\nObservation: ${r.observation}\n\nRemediation: ${r.remediation.join(" ")}\n\nAcceptance tests (not executed by the scanner): ${r.acceptance_tests.join(" ")}\n\nLimitations: ${r.limitations.join(" ")}\n\nReference pointers (not legal approval): ${r.sources.join(" ")}`,
    ),
  ].join("\n\n") + "\n",
);
const log = JSON.parse(
  await readFile("source-registry/retrieval-log.json", "utf8"),
);
const bodies = log.results.filter(
  (x) => x.http_status === 200 && x.bytes > 0,
).length;
await writeFile(
  "docs/legal-coverage.md",
  [
    "# Legal coverage",
    "**Zero legally verified obligations. No jurisdiction is certified or comprehensively covered.** Every record below is a research candidate. The catalog distinguishes statutes/regulations/directives from guidance/topics, standards and attestations. Unknown countries, industries and cities remain uncovered; absence is not non-applicability.",
    `The inventory has ${CATALOG.entries.length} entries. Industry composition offers ${Object.keys(INDUSTRIES).length} sectors, ${Object.keys(FEATURES).length} features and ${ARCHETYPES.length} archetypes. It does not enumerate every possible website or resolve interactions between laws. [Supplied research backlog](supplied-research-backlog.md) retains all categories in the starter.`,
    `Source retrieval attempted ${log.results.length} distinct URLs; ${bodies} returned HTTP 200 with a nonempty body. Other responses included empty challenges and access/server errors. Even nonempty HTTP 200 is not proof that the expected legal text was returned. See [retrieval log](../source-registry/retrieval-log.json) for individual dates, status and hashes. No checked/reviewer date below was invented.`,
    `All records have null legal review date, effective date, reviewer and next-review date; supported statutory controls are empty. Instrument links may point to original publications rather than currently amended/consolidated law. Research portals require locating exact instruments. Current commencement, amendments, litigation, territorial scope and exemptions remain outstanding.`,
    "| Jurisdiction | Instrument or research topic | Kind | Source | Review |\n| --- | --- | --- | --- | --- |",
    ...CATALOG.entries.map(
      (l) =>
        `| ${l.jurisdiction} | ${l.name} | ${l.kind} | ${l.primary_source ? `[Primary source pointer](${l.primary_source})` : "Missing — research required"} | unverified / research preview |`,
    ),
  ].join("\n\n") + "\n",
);
console.log(
  JSON.stringify({
    catalog: CATALOG.entries.length,
    industries: Object.keys(INDUSTRIES).length,
    features: Object.keys(FEATURES).length,
    archetypes: ARCHETYPES.length,
    nonempty_http_200: bodies,
  }),
);
