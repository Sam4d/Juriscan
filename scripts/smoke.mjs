import { execFileSync, spawnSync } from "node:child_process";
import path from "node:path";
import assert from "node:assert/strict";
const cwd = path.resolve(new URL("..", import.meta.url).pathname);
const run = (...args) =>
  JSON.parse(
    execFileSync(process.execPath, ["dist/cli.js", ...args], {
      cwd,
      encoding: "utf8",
    }),
  );
const vulnerable = run("scan", "--root", "fixtures/vulnerable");
const secure = run("scan", "--root", "fixtures/secure");
assert.equal(vulnerable.state, "complete");
assert.equal(vulnerable.findings.length, 12);
assert.equal(secure.findings.length, 0);
const restricted = spawnSync(
  process.execPath,
  [
    "--permission",
    `--allow-fs-read=${cwd}`,
    "--allow-fs-read=/proc/self/fd",
    "--require",
    "./scripts/offline-guard.cjs",
    "dist/cli.js",
    "scan",
    "--root",
    "fixtures/vulnerable",
  ],
  { cwd, encoding: "utf8", env: { PATH: process.env.PATH ?? "" } },
);
assert.equal(restricted.status, 0, restricted.stderr);
assert.equal(JSON.parse(restricted.stdout).findings.length, 12);
console.log(
  "PASS: vulnerable=12, negative=0; same scan succeeds with filesystem writes and child processes denied, network guard active, and no API keys.",
);

const ipRestricted = spawnSync(
  process.execPath,
  [
    "--permission",
    `--allow-fs-read=${cwd}`,
    "--allow-fs-read=/proc/self/fd",
    "--require",
    "./scripts/offline-guard.cjs",
    "dist/cli.js",
    "ip-review",
    "--root",
    "fixtures/secure",
  ],
  { cwd, encoding: "utf8", env: { PATH: process.env.PATH ?? "" } },
);
assert.equal(ipRestricted.status, 0, ipRestricted.stderr);
assert.equal(JSON.parse(ipRestricted.stdout).web_search_performed, false);
console.log(
  "PASS: offline IP review also succeeds with network/write/subprocess guards.",
);
