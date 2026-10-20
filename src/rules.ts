import type { Rule } from "./models.js";
function rule(
  id: string,
  title: string,
  domain: string,
  severity: Rule["severity"],
  observation: string,
  remediation: string[],
  acceptance_tests: string[],
  sources: string[],
  limitations: string[],
  confirmed = false,
): Rule {
  return {
    id,
    version: "1",
    title,
    domain,
    severity,
    observation,
    remediation,
    acceptance_tests,
    sources,
    limitations,
    classification: confirmed ? "confirmed_technical" : "needs_human_review",
    confidence: confirmed ? "high" : "medium",
    method: "bounded static pattern/AST analysis",
    missing_facts: [
      "Confirm deployment, intended use and compensating controls.",
      "Determine applicable obligations with qualified counsel.",
    ],
  };
}
export const RULES: Rule[] = [
  rule(
    "secret-literal",
    "Possible embedded credential",
    "security",
    "high",
    "A credential-shaped literal was found; its value is withheld.",
    [
      "Check whether this is a real credential; revoke/rotate through the provider if exposed.",
      "Move privileged credentials to a server-side secret manager; inspect history separately.",
    ],
    [
      "The literal is absent from source and generated public bundles.",
      "Provider confirms any exposed credential was revoked.",
    ],
    [
      "https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password",
    ],
    [
      "Patterns cannot prove a credential is live. Placeholder filtering can miss real keys.",
    ],
  ),
  rule(
    "client-privilege",
    "Privileged environment name in client code",
    "security",
    "high",
    "A client module or public environment variable references a privileged credential name.",
    [
      "Keep privileged operations in a server-only module.",
      "Use a public scoped key and enforce authorization at the server.",
    ],
    [
      "Production client assets contain no privileged secrets.",
      "Cross-user and anonymous access tests deny protected operations.",
    ],
    ["https://nextjs.org/docs/app/guides/environment-variables"],
    ["Static source does not prove a bundler actually exposed a value."],
  ),
  rule(
    "sql-rls-disabled",
    "Explicitly disabled row-level security",
    "access",
    "high",
    "A SQL ALTER TABLE statement disables row-level security.",
    [
      "Review grants and table sensitivity; enable RLS where appropriate with scoped policies.",
      "Test a migration and rollback on synthetic data before approval.",
    ],
    ["Anonymous and unrelated users cannot access private rows."],
    ["https://www.postgresql.org/docs/current/ddl-rowsecurity.html"],
    [
      "Statement order and deployed database state are not resolved. RLS is not always required.",
    ],
    true,
  ),
  rule(
    "sql-policy-open",
    "Unconditional SQL row policy",
    "access",
    "high",
    "A SQL policy contains a literal USING (true) or WITH CHECK (true) condition.",
    [
      "Confirm whether the table is intentionally public.",
      "Restrict protected rows using authenticated identity and ownership.",
    ],
    ["Cross-tenant reads and writes are denied for protected rows."],
    ["https://www.postgresql.org/docs/current/ddl-rowsecurity.html"],
    ["Roles, grants, policy combination and deployment require review."],
    true,
  ),
  rule(
    "firebase-open",
    "Unconditional Firebase permission",
    "access",
    "high",
    "A Firebase rule grants a read or write action with a literal true predicate.",
    [
      "Scope rules by authentication and resource ownership.",
      "Validate intentional public collections separately.",
    ],
    [
      "Firebase emulator denies unauthenticated writes and cross-user private reads.",
    ],
    ["https://firebase.google.com/docs/rules/basics"],
    ["Nested matches and actual deployment are not fully evaluated."],
    true,
  ),
  rule(
    "sensitive-log",
    "Sensitive named value passed to console",
    "privacy",
    "medium",
    "An executable console call contains a sensitive identifier or property.",
    [
      "Remove or redact the field before the log sink.",
      "Review downstream logging retention and access.",
    ],
    [
      "Capture synthetic sensitive inputs and assert no sensitive values appear in logs.",
    ],
    ["https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html"],
    [
      "Names indicate possible sensitive data; aliases and runtime flows are not traced.",
    ],
  ),
  rule(
    "tracker-import",
    "Analytics or advertising integration",
    "tracking",
    "info",
    "A known analytics or advertising module/script is referenced.",
    [
      "Inventory purpose, recipients and storage.",
      "Test load, consent refusal and revocation where applicable; do not invent consent requirements.",
    ],
    [
      "A browser test records requests and storage before and after user choices.",
    ],
    ["https://www.w3.org/TR/tracking-dnt/"],
    ["An import does not prove execution, collection or a consent violation."],
  ),
  rule(
    "deletion-local-only",
    "Local-only deletion indicator",
    "retention",
    "medium",
    "A deletion-named function clears browser storage without a source-visible remote operation.",
    [
      "Map account, processor, backup and retention flows.",
      "Implement and test the approved deletion process where required.",
    ],
    [
      "A synthetic deletion request is traced through authoritative stores and processors.",
    ],
    ["https://cheatsheetseries.owasp.org/cheatsheets/Privacy_Cheat_Sheet.html"],
    [
      "A remote workflow may exist elsewhere. This is a review question, not proof of missing deletion rights.",
    ],
  ),
  rule(
    "stripe-event-json",
    "Stripe event parsed directly from request JSON",
    "payments",
    "high",
    "A webhook-named function reads request JSON without a local constructEvent call.",
    [
      "Verify signatures with the raw request body and endpoint secret before trusting an event.",
      "Add idempotent event processing.",
    ],
    [
      "Invalid or missing signatures and replayed events cannot trigger duplicate fulfillment.",
    ],
    ["https://docs.stripe.com/webhooks/signature"],
    [
      "Wrapper verification or delegated middleware may exist. Only function-local evidence is examined.",
    ],
  ),
  rule(
    "image-alt",
    "Static image missing alternative text",
    "accessibility",
    "medium",
    "A JSX img element lacks alt and has no spread attributes.",
    [
      'Provide meaningful alt text, or alt="" for decorative images after review.',
    ],
    [
      "Rendered images expose appropriate alternatives to assistive technology.",
    ],
    ["https://www.w3.org/WAI/WCAG22/Understanding/non-text-content.html"],
    ["JSX only; context and rendered accessibility require manual testing."],
    true,
  ),
  rule(
    "input-name",
    "Input lacks a source-visible accessible name",
    "accessibility",
    "medium",
    "A non-hidden JSX input has no accessible-name attribute or associated label in this file.",
    ["Associate a visible label or appropriate accessible name."],
    [
      "Each rendered control has a meaningful accessible name; test keyboard and screen reader behavior.",
    ],
    ["https://www.w3.org/WAI/WCAG22/Understanding/labels-or-instructions.html"],
    ["Labels supplied by components or other files may be missed."],
  ),
  rule(
    "blank-target",
    "Blank-target link without explicit opener isolation",
    "security",
    "low",
    'A JSX link uses target="_blank" without explicit noopener/noreferrer.',
    [
      'Add rel="noopener" when supporting browsers that need explicit isolation.',
    ],
    ["The opened page cannot access window.opener in supported browsers."],
    [
      "https://developer.mozilla.org/en-US/docs/Web/HTML/Reference/Attributes/rel/noopener",
    ],
    [
      "Modern browsers implicitly isolate many blank-target links. This is hardening, not a confirmed exploit.",
    ],
  ),
];
export const RULE_MAP = new Map(RULES.map((r) => [r.id, r]));
