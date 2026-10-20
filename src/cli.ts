#!/usr/bin/env node
import path from "node:path";
import { IPInput, ipReview } from "./ip.js";
import { ipWebReview } from "./ip-web.js";
import { parseArgs } from "node:util";
import { z } from "zod";
import { scan } from "./scanner.js";
import { startMcp, capabilities } from "./mcp.js";
import { RULES } from "./rules.js";
import { intake, industryChecklist, CATALOG } from "./legal.js";
import { VERSION, SafeError } from "./models.js";
import { report, masterPrompt, plan, exitCode } from "./reports.js";
const usage = `Juriscan ${VERSION} (Linux / Node 24)\n\nCommands:\n  mcp --allow-root /absolute/project   Start stdio MCP (repeat --allow-root for multiple projects)\n  scan --root ./project --format json|markdown|sarif|text [--fail-on none|critical|high|medium|low]\n  profile --root ./project\n  plan --root ./project\n  prompt --root ./project\n  intake --answers '{"target_markets":{"state":"known","value":["EU"]}}'\n  checklist --industries healthcare --features subscriptions,ai --jurisdictions EU,US-FED\n  ip-review --root ./project [--brands BrandOne,BrandTwo]\n  ip-web --root ./project --reference-url https://approved.example/reference --allow-domain approved.example --authorize-network\n  rules | coverage | capabilities | doctor | --version\n\nReports go to stdout. Redirect explicitly to a file outside scanned source. No project code executes.\n`;
async function main() {
  const { values: v, positionals } = parseArgs({
    allowPositionals: true,
    strict: true,
    options: {
      help: { type: "boolean" },
      version: { type: "boolean" },
      root: { type: "string" },
      "allow-root": { type: "string", multiple: true },
      format: { type: "string" },
      "fail-on": { type: "string" },
      answers: { type: "string" },
      industries: { type: "string" },
      features: { type: "string" },
      jurisdictions: { type: "string" },
      "max-files": { type: "string" },
      brands: { type: "string" },
      "reference-url": { type: "string", multiple: true },
      "allow-domain": { type: "string", multiple: true },
      "authorize-network": { type: "boolean" },
    },
  });
  if (v.help) {
    console.log(usage);
    return;
  }
  if (v.version) {
    console.log(VERSION);
    return;
  }
  const command = positionals[0];
  if (positionals.length > 1)
    throw new SafeError(
      "INVALID_ARGUMENTS",
      "Unexpected positional arguments.",
    );
  const output = (x: unknown) =>
    console.log(typeof x === "string" ? x : JSON.stringify(x, null, 2));
  if (command === "mcp") {
    if (!v["allow-root"]?.length)
      throw new SafeError(
        "ROOT_REQUIRED",
        "MCP requires at least one explicit --allow-root.",
      );
    await startMcp(v["allow-root"].map((r) => path.resolve(r)));
    return;
  }
  if (command === "capabilities") {
    output(capabilities());
    return;
  }
  if (command === "rules") {
    output(RULES);
    return;
  }
  if (command === "coverage") {
    output(CATALOG);
    return;
  }
  if (command === "doctor") {
    output({
      node: process.versions.node,
      platform: process.platform,
      supported:
        process.platform === "linux" && process.versions.node.startsWith("24."),
      network_required: false,
      api_key_required: false,
    });
    if (process.platform !== "linux") process.exitCode = 2;
    return;
  }
  if (command === "intake") {
    output(intake(JSON.parse(v.answers ?? "{}")));
    return;
  }
  if (command === "checklist") {
    output(
      industryChecklist({
        industries: v.industries?.split(",") ?? [],
        features: v.features?.split(",") ?? [],
        jurisdictions: v.jurisdictions?.split(",") ?? [],
      }),
    );
    return;
  }
  if (command === "ip-review" || command === "ip-web") {
    if (!v.root)
      throw new SafeError("ROOT_REQUIRED", "An explicit --root is required.");
    const root = path.resolve(v.root);
    const result =
      command === "ip-review"
        ? await ipReview(
            root,
            [root],
            IPInput.parse({ root, brand_terms: v.brands?.split(",") ?? [] })
              .brand_terms,
          )
        : await ipWebReview(
            {
              root,
              reference_urls: v["reference-url"] ?? [],
              allowed_domains: v["allow-domain"] ?? [],
              authorized_network: v["authorize-network"] ?? false,
            },
            [root],
          );
    output(result);
    process.exitCode = result.state === "complete" ? 0 : 3;
    return;
  }
  if (!command || !["scan", "profile", "plan", "prompt"].includes(command))
    throw new SafeError(
      "INVALID_COMMAND",
      "Use --help for supported commands.",
    );
  if (!v.root)
    throw new SafeError("ROOT_REQUIRED", "An explicit --root is required.");
  const root = path.resolve(v.root),
    format = z
      .enum(["json", "markdown", "sarif", "text"])
      .parse(v.format ?? "json");
  const failOn = z
    .enum(["none", "critical", "high", "medium", "low"])
    .parse(v["fail-on"] ?? "none");
  const options = v["max-files"]
    ? { limits: { max_files: Number(v["max-files"]) } }
    : {};
  const result = await scan(root, [root], options);
  if (command === "scan") output(report(result, format));
  if (command === "profile")
    output({
      scan_id: result.id,
      state: result.state,
      files_scanned: result.files_scanned,
      observed_domains: [...new Set(result.findings.map((f) => f.domain))],
      omissions: result.omissions,
    });
  if (command === "plan") output(plan(result));
  if (command === "prompt") output(masterPrompt(result));
  process.exitCode = exitCode(result, failOn);
}
main().catch((e) => {
  const error =
    e instanceof SafeError
      ? { code: e.code, message: e.message }
      : {
          code: "INVALID_ARGUMENTS_OR_INPUT",
          message:
            "Arguments or input could not be processed. Use --help. No project content is included in this error.",
        };
  process.stderr.write(JSON.stringify(error) + "\n");
  process.exitCode = 2;
});
