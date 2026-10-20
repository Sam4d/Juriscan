import { readFileSync } from "node:fs";
import { beforeAll, afterAll, it, expect } from "vitest";
import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import path from "node:path";
const root = path.resolve("fixtures/vulnerable");
let client: Client;
let scanId: string;
beforeAll(async () => {
  client = new Client({ name: "juriscan-reference-harness", version: "1.0.0" });
  await client.connect(
    new StdioClientTransport({
      command: process.execPath,
      args: ["dist/cli.js", "mcp", "--allow-root", root],
      stderr: "pipe",
      env: { PATH: process.env.PATH ?? "" },
    }),
  );
}, 30000);
afterAll(async () => {
  await client?.close();
});
async function call(name: string, args: Record<string, unknown> = {}) {
  const r = await client.callTool({ name, arguments: args });
  expect(r.isError, JSON.stringify(r)).not.toBe(true);
  return r.structuredContent as Record<string, any>;
}
it("reference-client handshake and discovery expose implemented tools", async () => {
  const list = await client.listTools();
  expect(list.tools.length).toBe(25);
  expect(list.tools).toEqual(
    JSON.parse(readFileSync("docs/mcp-tool-schemas.json", "utf8")),
  );
  expect(
    list.tools.find((t) => t.name === "juriscan_scan")?.inputSchema,
  ).toBeDefined();
  const r = await call("juriscan_capabilities");
  expect(r.legal_rulepacks_verified).toBe(0);
  expect((await call("juriscan_health")).ready).toBe(true);
});
it("performs real end-to-end scan, findings, plan, prompt, comparison and reports", async () => {
  const s = await call("juriscan_scan", { root });
  scanId = s.id;
  expect(s.state).toBe("complete");
  expect(s.findings_count).toBe(12);
  const f = await call("juriscan_findings", { scan_id: scanId, limit: 5 });
  expect(f.items.length).toBe(5);
  expect(f.next_offset).toBe(5);
  expect(f.total).toBe(12);
  const one = await call("juriscan_get_finding", {
    scan_id: scanId,
    finding_id: f.items[0].id,
  });
  expect(one.legal_status).toBe("not_assessed");
  expect(
    (await call("juriscan_remediation_plan", { scan_id: scanId })).tasks.length,
  ).toBe(12);
  expect(
    (await call("juriscan_generate_master_prompt", { scan_id: scanId })).prompt,
  ).toContain("Zero legally verified");
  expect(
    (await call("juriscan_verify", { scan_id: scanId })).still_present.length,
  ).toBe(12);
  expect(
    (
      await call("juriscan_compare", {
        base_scan_id: scanId,
        head_scan_id: scanId,
      })
    ).new,
  ).toEqual([]);
  for (const format of ["json", "markdown", "text", "sarif"])
    expect(
      (await call("juriscan_report", { scan_id: scanId, format })).report,
    ).toBeDefined();
  const res = await client.readResource({
    uri: `juriscan://scans/${scanId}/summary`,
  });
  expect(JSON.stringify(res)).toContain(scanId);
  expect((await call("juriscan_scan_status", { scan_id: scanId })).state).toBe(
    "complete",
  );
});
it("resources and prompts are discoverable and usable", async () => {
  const resources = await client.listResources();
  expect(resources.resources.length).toBe(4);
  for (const r of resources.resources)
    expect((await client.readResource({ uri: r.uri })).contents.length).toBe(1);
  const prompts = await client.listPrompts();
  expect(prompts.prompts.length).toBe(4);
  for (const p of prompts.prompts)
    expect(JSON.stringify(await client.getPrompt({ name: p.name }))).toContain(
      "qualified reviewer",
    );
});
it("metadata and legal/industry tools return candid scoped results", async () => {
  for (const name of [
    "juriscan_version",
    "juriscan_list_jurisdictions",
    "juriscan_list_rules",
    "juriscan_legal_catalog",
    "juriscan_industry_taxonomy",
    "juriscan_rulepack_status",
  ])
    expect(await call(name)).toBeDefined();
  expect((await call("juriscan_get_rule", { rule_id: "image-alt" })).id).toBe(
    "image-alt",
  );
  expect(
    (await call("juriscan_legal_intake", { answers: {} })).questions.length,
  ).toBeGreaterThan(10);
  expect(
    (await call("juriscan_applicability", { facts: {}, jurisdictions: ["EU"] }))
      .candidates[0].status,
  ).toBe("unknown");
  expect(
    (
      await call("juriscan_industry_checklist", {
        industries: ["healthcare"],
        features: ["ai"],
        jurisdictions: ["EU"],
      })
    ).exhaustive,
  ).toBe(false);
  expect((await call("juriscan_project_profile", { root })).files_scanned).toBe(
    4,
  );
});
it("denies outside-root tool calls and invalid schemas with safe errors", async () => {
  const r = await client.callTool({
    name: "juriscan_scan",
    arguments: { root: "/etc" },
  });
  expect(r.isError).toBe(true);
  expect(JSON.stringify(r)).toContain("ROOT_DENIED");
  const invalid = await client.callTool({
    name: "juriscan_findings",
    arguments: { scan_id: "bad", limit: 10000 },
  });
  expect(invalid.isError).toBe(true);
});
it("purge discards prior session findings", async () => {
  await call("juriscan_purge");
  const r = await client.callTool({
    name: "juriscan_scan_status",
    arguments: { scan_id: scanId },
  });
  expect(r.isError).toBe(true);
});
it("negotiates the pinned modern protocol with the official reference SDK", async () => {
  const modern = new Client(
    { name: "juriscan-modern-harness", version: "1.0.0" },
    { versionNegotiation: { mode: { pin: "2026-07-28" } } },
  );
  try {
    await modern.connect(
      new StdioClientTransport({
        command: process.execPath,
        args: ["dist/cli.js", "mcp", "--allow-root", root],
        stderr: "pipe",
        env: { PATH: process.env.PATH ?? "" },
      }),
    );
    const tools = await modern.listTools();
    expect(tools.tools.some((t) => t.name === "juriscan_scan")).toBe(true);
    const result = await modern.callTool({
      name: "juriscan_health",
      arguments: {},
    });
    expect(result.isError).not.toBe(true);
  } finally {
    await modern.close();
  }
});
it("IP tools report review questions and require separate explicit web authorization", async () => {
  const r = await call("juriscan_ip_review", { root });
  expect(r.legal_status).toBe("not_assessed");
  expect(r.web_search_performed).toBe(false);
  const denied = await client.callTool({
    name: "juriscan_ip_web_compare",
    arguments: {
      root,
      reference_urls: ["https://example.com/source"],
      allowed_domains: ["example.com"],
      authorized_network: false,
    },
  });
  expect(denied.isError).toBe(true);
  const tools = await client.listTools();
  expect(
    tools.tools.find((t) => t.name === "juriscan_ip_web_compare")!.annotations!
      .openWorldHint,
  ).toBe(true);
  expect(
    tools.tools.find((t) => t.name === "juriscan_ip_review")!.annotations!
      .openWorldHint,
  ).toBe(false);
});
