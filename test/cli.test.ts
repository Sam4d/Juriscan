import { it, expect } from "vitest";
import { spawnSync } from "node:child_process";
const run = (args: string[]) =>
  spawnSync(process.execPath, ["dist/cli.js", ...args], {
    encoding: "utf8",
    timeout: 20000,
    env: { PATH: process.env.PATH ?? "" },
  });
it("built CLI provides working commands with explicit exit codes", () => {
  expect(run(["--version"]).stdout.trim()).toBe("0.1.0-alpha.1");
  expect(run(["--help"]).status).toBe(0);
  expect(run(["ip-review", "--root", "fixtures/secure"]).status).toBe(0);
  expect(
    run([
      "ip-web",
      "--root",
      "fixtures/secure",
      "--reference-url",
      "https://example.com/source",
      "--allow-domain",
      "example.com",
    ]).status,
  ).toBe(2);
  expect(
    run(["scan", "--root", "fixtures/vulnerable", "--fail-on", "high"]).status,
  ).toBe(1);
  expect(
    run(["scan", "--root", "fixtures/secure", "--fail-on", "high"]).status,
  ).toBe(0);
  expect(
    run(["scan", "--root", "fixtures/vulnerable", "--max-files", "1"]).status,
  ).toBe(3);
  for (const command of ["profile", "plan", "prompt"])
    expect(run([command, "--root", "fixtures/vulnerable"]).status).toBe(0);
  for (const command of [
    "doctor",
    "capabilities",
    "rules",
    "coverage",
    "intake",
  ])
    expect(run([command]).status).toBe(0);
  expect(
    run([
      "checklist",
      "--industries",
      "healthcare",
      "--features",
      "ai,subscriptions",
      "--jurisdictions",
      "EU,ZZ",
    ]).status,
  ).toBe(0);
  for (const args of [
    ["scan"],
    ["mcp"],
    ["scan", "--root", "fixtures/secure", "--format", "evil"],
    ["wat"],
    ["scan", "--root", "fixtures/secure", "--max-files", "oops"],
  ])
    expect(run(args).status).toBe(2);
}, 20000);
