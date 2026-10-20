# Getting started

Use the commands in the [README](../README.md) with Linux and Node 24.19.0. Dependency versions and integrity hashes are pinned in `pnpm-lock.yaml`; installation scripts are disabled in `.npmrc`. Do not execute the synthetic fixtures.

`pnpm build` produces the CLI and SDK-independent library in `dist/`. `pnpm test` rebuilds before exercising detector, filesystem, legal-intake, reporting, CLI and MCP tests. `pnpm smoke` verifies the documented vulnerable/negative fixtures and guarded offline operation. `pnpm check` also checks types and documentation links.

To scan your own project, give `node dist/cli.js scan --root /absolute/project`. CLI `--root` explicitly authorizes that invocation. The MCP server separately requires `--allow-root`; its tool arguments cannot grant broader access. Keep reports outside the scanned root to avoid scanning your own prior outputs.

Interpret a finding by reading its classification, location, observation, missing facts, acceptance tests and limitations. `confirmed_technical` means the specific syntactic condition is present, not that access was exploited or a law violated. `needs_human_review` is a heuristic. `legal_status` is always `not_assessed`.

For a portable local archive, run `pnpm build` then `npm pack --ignore-scripts`. Install that archive into an isolated directory with `npm install --ignore-scripts /path/to/archive.tgz`, then run its local `node_modules/.bin/juriscan`. This is a development installation, not a published npm release. Avoid using `npx juriscan`: that name is not established by this project.
