// Explicit maintainer research command. Never imported by the scanner or MCP server.
// Uses curl's configured HTTPS proxy and system trust; never disables TLS verification.
import { readFile, writeFile, mkdtemp, rm } from "node:fs/promises";
import { createHash } from "node:crypto";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { tmpdir } from "node:os";
import path from "node:path";
const exec = promisify(execFile);
const catalog = JSON.parse(
  await readFile(
    new URL("../source-registry/laws.json", import.meta.url),
    "utf8",
  ),
);
const allUrls = [
  ...new Set(catalog.entries.map((x) => x.primary_source).filter(Boolean)),
];
const selected = process.argv.slice(2);
if (selected.some((url) => !allUrls.includes(url)))
  throw new Error("Selected URL must be in the registry");
const urls = selected.length ? selected : allUrls;
const previous = selected.length
  ? JSON.parse(
      await readFile(
        new URL("../source-registry/retrieval-log.json", import.meta.url),
        "utf8",
      ),
    ).results
  : [];
const temp = await mkdtemp(path.join(tmpdir(), "juriscan-sources-"));
const results = [];
let i = 0;
async function worker() {
  while (i < urls.length) {
    const index = i++,
      url = urls[index],
      checked_at = new Date().toISOString(),
      dest = path.join(temp, String(index));
    try {
      const { stdout } = await exec(
        "curl",
        [
          "--silent",
          "--show-error",
          "--location",
          "--proto",
          "=https",
          "--proto-redir",
          "=https",
          "--max-time",
          "12",
          "--max-filesize",
          "2000000",
          "--output",
          dest,
          "--write-out",
          "%{http_code}\n%{url_effective}",
          url,
        ],
        { timeout: 15000, maxBuffer: 10000 },
      );
      const [code, final_url] = stdout.trim().split("\n");
      const body = await readFile(dest);
      results.push({
        url,
        checked_at,
        http_status: Number(code),
        final_url,
        bytes: body.length,
        sha256: createHash("sha256").update(body).digest("hex"),
        verification: "retrieval_only_not_legal_review",
      });
    } catch (error) {
      results.push({
        url,
        checked_at,
        http_status: null,
        error: /CONNECT tunnel failed, response 403/.test(error.stderr ?? "")
          ? "proxy_denied"
          : "unavailable_or_network_restricted",
        verification: "not_retrieved",
      });
    }
  }
}
try {
  await Promise.all(Array.from({ length: 6 }, worker));
  const attempted = results.length;
  results.push(
    ...previous.filter((x) => allUrls.includes(x.url) && !urls.includes(x.url)),
  );
  results.sort((a, b) => a.url.localeCompare(b.url));
  await writeFile(
    new URL("../source-registry/retrieval-log.json", import.meta.url),
    JSON.stringify(
      {
        notice:
          "HTTP success and response hashes do not verify legal text, current law or legal review. No source text is redistributed. Retrieval metadata is separate from legal source review status.",
        results,
      },
      null,
      2,
    ) + "\n",
  );
  console.log(
    JSON.stringify({
      attempted_this_run: attempted,
      recorded: results.length,
      http_success: results.filter(
        (x) => x.http_status >= 200 && x.http_status < 300,
      ).length,
      proxy_denied: results.filter((x) => x.error === "proxy_denied").length,
      unavailable: results.filter((x) => !x.http_status || x.http_status >= 400)
        .length,
    }),
  );
} finally {
  await rm(temp, { recursive: true, force: true });
}
