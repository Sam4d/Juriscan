import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { performance } from "node:perf_hooks";
import { scan } from "../dist/scanner.js";
const root = await mkdtemp(path.join(tmpdir(), "juriscan-benchmark-"));
try {
  for (let i = 0; i < 1000; i++)
    await writeFile(
      path.join(root, `module-${String(i).padStart(4, "0")}.ts`),
      `export const value${i} = ${i};\n`,
    );
  const start = performance.now();
  const s = await scan(root, [root]);
  const result = {
    measured_at: new Date().toISOString(),
    node: process.version,
    platform: process.platform,
    target: "1000 generated trivial TypeScript modules; no findings expected",
    files: s.files_scanned,
    bytes: s.bytes_scanned,
    state: s.state,
    findings: s.findings.length,
    elapsed_ms: Math.round(performance.now() - start),
    peak_rss_kib: process.resourceUsage().maxRSS,
    limitations:
      "Single warm process, small synthetic files, shared container; not a real-project throughput guarantee or detection/legal accuracy benchmark.",
  };
  await writeFile(
    "docs/benchmark-result.json",
    JSON.stringify(result, null, 2) + "\n",
  );
  console.log(JSON.stringify(result));
} finally {
  await rm(root, { recursive: true, force: true });
}
