import { it, expect } from "vitest";
import { readFileSync } from "node:fs";
import path from "node:path";
import Ajv from "ajv";
import { scan } from "../src/scanner.js";
import { sarif, masterPrompt, plan } from "../src/reports.js";
import { FindingSchema } from "../src/models.js";
import { z } from "zod";
it("SARIF matches the vendored official schema distribution", async () => {
  const ajv = new Ajv({ strict: false, validateFormats: false });
  const schema = JSON.parse(
    readFileSync("test/vendor/sarif-2.1.0.schema.json", "utf8"),
  );
  const validate = ajv.compile(schema);
  const root = path.resolve("fixtures/vulnerable");
  const s = await scan(root, [root]);
  expect(validate(sarif(s)), JSON.stringify(validate.errors)).toBe(true);
});
it("findings validate as independent JSON Schema data", async () => {
  const ajv = new Ajv({ strict: false });
  const schema = z.toJSONSchema(FindingSchema, { target: "draft-7" });
  const validate = ajv.compile(schema);
  const root = path.resolve("fixtures/vulnerable");
  for (const f of (await scan(root, [root])).findings)
    expect(validate(f), JSON.stringify(validate.errors)).toBe(true);
});
it("remediation is deterministic and keeps approval gates and unrun acceptance tests", async () => {
  const root = path.resolve("fixtures/vulnerable");
  const s = await scan(root, [root]);
  expect(masterPrompt(s)).toBe(masterPrompt(s));
  expect(plan(s).tasks).toHaveLength(12);
  expect(masterPrompt(s)).toContain("Tests to execute (not yet run)");
  expect(() => masterPrompt(s, 2000)).toThrow("output limit");
});
