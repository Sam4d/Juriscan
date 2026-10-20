# Detector contracts

Generated from shipped rule metadata. `confirmed_technical` confirms the syntactic condition only. All legal applicability is not assessed. Each detector has three positive, three negative and one ambiguous case in test/detectors.test.ts. These examples are a controlled test set, not real-world accuracy guarantees.

## secret-literal

Possible embedded credential. Classification: needs_human_review; severity: high; confidence: medium.

Observation: A credential-shaped literal was found; its value is withheld.

Remediation: Check whether this is a real credential; revoke/rotate through the provider if exposed. Move privileged credentials to a server-side secret manager; inspect history separately.

Acceptance tests (not executed by the scanner): The literal is absent from source and generated public bundles. Provider confirms any exposed credential was revoked.

Limitations: Patterns cannot prove a credential is live. Placeholder filtering can miss real keys.

Reference pointers (not legal approval): https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password

## client-privilege

Privileged environment name in client code. Classification: needs_human_review; severity: high; confidence: medium.

Observation: A client module or public environment variable references a privileged credential name.

Remediation: Keep privileged operations in a server-only module. Use a public scoped key and enforce authorization at the server.

Acceptance tests (not executed by the scanner): Production client assets contain no privileged secrets. Cross-user and anonymous access tests deny protected operations.

Limitations: Static source does not prove a bundler actually exposed a value.

Reference pointers (not legal approval): https://nextjs.org/docs/app/guides/environment-variables

## sql-rls-disabled

Explicitly disabled row-level security. Classification: confirmed_technical; severity: high; confidence: high.

Observation: A SQL ALTER TABLE statement disables row-level security.

Remediation: Review grants and table sensitivity; enable RLS where appropriate with scoped policies. Test a migration and rollback on synthetic data before approval.

Acceptance tests (not executed by the scanner): Anonymous and unrelated users cannot access private rows.

Limitations: Statement order and deployed database state are not resolved. RLS is not always required.

Reference pointers (not legal approval): https://www.postgresql.org/docs/current/ddl-rowsecurity.html

## sql-policy-open

Unconditional SQL row policy. Classification: confirmed_technical; severity: high; confidence: high.

Observation: A SQL policy contains a literal USING (true) or WITH CHECK (true) condition.

Remediation: Confirm whether the table is intentionally public. Restrict protected rows using authenticated identity and ownership.

Acceptance tests (not executed by the scanner): Cross-tenant reads and writes are denied for protected rows.

Limitations: Roles, grants, policy combination and deployment require review.

Reference pointers (not legal approval): https://www.postgresql.org/docs/current/ddl-rowsecurity.html

## firebase-open

Unconditional Firebase permission. Classification: confirmed_technical; severity: high; confidence: high.

Observation: A Firebase rule grants a read or write action with a literal true predicate.

Remediation: Scope rules by authentication and resource ownership. Validate intentional public collections separately.

Acceptance tests (not executed by the scanner): Firebase emulator denies unauthenticated writes and cross-user private reads.

Limitations: Nested matches and actual deployment are not fully evaluated.

Reference pointers (not legal approval): https://firebase.google.com/docs/rules/basics

## sensitive-log

Sensitive named value passed to console. Classification: needs_human_review; severity: medium; confidence: medium.

Observation: An executable console call contains a sensitive identifier or property.

Remediation: Remove or redact the field before the log sink. Review downstream logging retention and access.

Acceptance tests (not executed by the scanner): Capture synthetic sensitive inputs and assert no sensitive values appear in logs.

Limitations: Names indicate possible sensitive data; aliases and runtime flows are not traced.

Reference pointers (not legal approval): https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html

## tracker-import

Analytics or advertising integration. Classification: needs_human_review; severity: info; confidence: medium.

Observation: A known analytics or advertising module/script is referenced.

Remediation: Inventory purpose, recipients and storage. Test load, consent refusal and revocation where applicable; do not invent consent requirements.

Acceptance tests (not executed by the scanner): A browser test records requests and storage before and after user choices.

Limitations: An import does not prove execution, collection or a consent violation.

Reference pointers (not legal approval): https://www.w3.org/TR/tracking-dnt/

## deletion-local-only

Local-only deletion indicator. Classification: needs_human_review; severity: medium; confidence: medium.

Observation: A deletion-named function clears browser storage without a source-visible remote operation.

Remediation: Map account, processor, backup and retention flows. Implement and test the approved deletion process where required.

Acceptance tests (not executed by the scanner): A synthetic deletion request is traced through authoritative stores and processors.

Limitations: A remote workflow may exist elsewhere. This is a review question, not proof of missing deletion rights.

Reference pointers (not legal approval): https://cheatsheetseries.owasp.org/cheatsheets/Privacy_Cheat_Sheet.html

## stripe-event-json

Stripe event parsed directly from request JSON. Classification: needs_human_review; severity: high; confidence: medium.

Observation: A webhook-named function reads request JSON without a local constructEvent call.

Remediation: Verify signatures with the raw request body and endpoint secret before trusting an event. Add idempotent event processing.

Acceptance tests (not executed by the scanner): Invalid or missing signatures and replayed events cannot trigger duplicate fulfillment.

Limitations: Wrapper verification or delegated middleware may exist. Only function-local evidence is examined.

Reference pointers (not legal approval): https://docs.stripe.com/webhooks/signature

## image-alt

Static image missing alternative text. Classification: confirmed_technical; severity: medium; confidence: high.

Observation: A JSX img element lacks alt and has no spread attributes.

Remediation: Provide meaningful alt text, or alt="" for decorative images after review.

Acceptance tests (not executed by the scanner): Rendered images expose appropriate alternatives to assistive technology.

Limitations: JSX only; context and rendered accessibility require manual testing.

Reference pointers (not legal approval): https://www.w3.org/WAI/WCAG22/Understanding/non-text-content.html

## input-name

Input lacks a source-visible accessible name. Classification: needs_human_review; severity: medium; confidence: medium.

Observation: A non-hidden JSX input has no accessible-name attribute or associated label in this file.

Remediation: Associate a visible label or appropriate accessible name.

Acceptance tests (not executed by the scanner): Each rendered control has a meaningful accessible name; test keyboard and screen reader behavior.

Limitations: Labels supplied by components or other files may be missed.

Reference pointers (not legal approval): https://www.w3.org/WAI/WCAG22/Understanding/labels-or-instructions.html

## blank-target

Blank-target link without explicit opener isolation. Classification: needs_human_review; severity: low; confidence: medium.

Observation: A JSX link uses target="\_blank" without explicit noopener/noreferrer.

Remediation: Add rel="noopener" when supporting browsers that need explicit isolation.

Acceptance tests (not executed by the scanner): The opened page cannot access window.opener in supported browsers.

Limitations: Modern browsers implicitly isolate many blank-target links. This is hardening, not a confirmed exploit.

Reference pointers (not legal approval): https://developer.mozilla.org/en-US/docs/Web/HTML/Reference/Attributes/rel/noopener
