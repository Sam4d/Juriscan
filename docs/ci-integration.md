# CI and reproducibility

`.github/workflows/ci.yml` runs installation with the frozen pnpm lockfile and package scripts disabled, type checks, tests, documentation links, formatting and the guarded smoke scan on Linux/Node 24. Actions are pinned to full official upstream commit IDs resolved during implementation. Pull-request jobs use read-only repository permissions; no `pull_request_target`, deployment secrets or publication credentials are used.

The workflow has been exercised locally through its underlying commands. A GitHub Actions run is only verified after GitHub reports its result; a committed workflow is not proof of remote CI success.

For another repository, use an explicitly authorized root and write output outside the scanned source:

```sh
node /absolute/Juriscan/dist/cli.js scan --root /absolute/project --format sarif
```

Redirect stdout to your artifact location as appropriate and preserve the process exit status. Do not append `|| true` and then report a pass. Add `--fail-on high` to gate only confirmed technical high/critical observations. Partial scans exit 3; unknown legal applicability never becomes a violation.

SARIF is validated against a vendored SchemaStore distribution of SARIF 2.1.0. GitHub code-scanning upload and repository security features depend on the account/repository configuration and are not enabled by this project. Treat reports as sensitive. No baseline/suppression mechanism, signed release, npm deployment or automatic legal-source-update workflow is shipped.
