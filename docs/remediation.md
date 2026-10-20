# Remediation and verification

Plans derive only from retained findings. They sort by severity and stable ID, with a shared prerequisite: confirm scope and reproduce the observation using synthetic data. Each task preserves classification, path, rule reference, remediation steps and unexecuted acceptance tests. No tool edits source, rotates keys, changes a database, bills customers or deploys software.

Generated master prompts carry source snapshot and scan/rule versions, zero-verified-legal-coverage disclosure, safety boundaries, confirmed syntactic observations, human-review observations, ordered tasks and approval gates, acceptance criteria, execution sequence and completion reporting requirements. Repository source text is excluded; path strings are quoted and marked untrusted. Prompt length is bounded; a too-large plan fails clearly rather than truncating safety instructions.

Ask the host to inspect, explain, propose a bounded patch, obtain required approvals, run tests, then report changes and unresolved facts. Credential rotation, production writes/deletion, billing, age/consent policy, legal wording and deployment need explicit human control. Roll back through your normal version-control/deployment procedure; Juriscan has no patch or rollback mechanism.

`juriscan_verify` re-runs the same detector selection and limits at the same root. Comparison reports still-present/new/no-longer-observed findings; partial, cancelled or differently scoped runs cannot establish absence. IDs/fingerprints combine rule ID, relative path and occurrence ordinal. Line shifts retain identity, but inserting/removing same-rule occurrences or renaming files can change matches. Source hashes establish changed bytes, not semantic equivalence or deployed fixes.

Static disappearance is not “fixed legally.” No application tests run within verification, and manual validation always remains required. A negative fixture is just an expected non-trigger for the limited detector set.
