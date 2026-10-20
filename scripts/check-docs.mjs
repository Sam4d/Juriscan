import { readdir, readFile, stat } from "node:fs/promises";
import path from "node:path";
import assert from "node:assert/strict";
import { CATALOG } from "../dist/legal.js";
import { RULES } from "../dist/rules.js";
async function walk(dir) {
  const result = [];
  for (const e of await readdir(dir, { withFileTypes: true })) {
    if (["node_modules", ".git", "dist"].includes(e.name)) continue;
    const p = path.join(dir, e.name);
    if (e.isDirectory()) result.push(...(await walk(p)));
    else if (e.name.endsWith(".md")) result.push(p);
  }
  return result;
}
const failures = [];
for (const file of await walk(".")) {
  const text = await readFile(file, "utf8");
  for (const m of text.matchAll(/\[[^\]]*\]\(([^)]+)\)/g)) {
    const link = m[1].split("#")[0];
    if (!link || /^[a-z]+:/i.test(link)) continue;
    try {
      await stat(path.resolve(path.dirname(file), link));
    } catch {
      failures.push(`${file}: ${link}`);
    }
  }
}
assert.deepEqual(failures, [], "Broken local documentation links");
assert.equal(
  new Set(CATALOG.entries.map((x) => x.id)).size,
  CATALOG.entries.length,
);
assert.equal(CATALOG.verified_active, 0);
const docs = await readFile("docs/detectors.md", "utf8");
for (const r of RULES) assert.ok(docs.includes(r.id));
const schemas = JSON.parse(
  await readFile("docs/mcp-tool-schemas.json", "utf8"),
);
assert.equal(schemas.length, 25);
console.log(
  "PASS: local Markdown links, catalog identity/review invariants, detector documentation and tool schema inventory.",
);
