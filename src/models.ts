import { z } from "zod";
export const VERSION = "0.1.0-alpha.1";
export const DISCLAIMER =
  "Juriscan identifies technical observations and research questions from limited evidence. It does not give legal advice, determine full legal compliance, or guarantee prevention of lawsuits, penalties, or security incidents. Obtain qualified review of applicable law and actual business practices.";
export const Severity = z.enum(["critical", "high", "medium", "low", "info"]);
export const FindingSchema = z
  .object({
    schema_version: z.literal("1"),
    id: z.string(),
    fingerprint: z.string().regex(/^[a-f0-9]{64}$/),
    rule_id: z.string(),
    rule_version: z.literal("1"),
    title: z.string(),
    domain: z.string(),
    classification: z.enum([
      "confirmed_technical",
      "needs_human_review",
      "informational",
    ]),
    severity: Severity,
    confidence: z.enum(["high", "medium", "low"]),
    location: z.object({ path: z.string(), line: z.number().int().positive() }),
    evidence: z.object({
      id: z.string(),
      observation: z.string(),
      method: z.string(),
      source_hash: z.string(),
    }),
    legal_status: z.literal("not_assessed"),
    legal_refs: z.array(z.string()).max(0),
    missing_facts: z.array(z.string()),
    remediation: z.array(z.string()),
    acceptance_tests: z.array(z.string()),
    limitations: z.array(z.string()),
    verification: z.literal("not_run"),
  })
  .strict();
export type Finding = z.infer<typeof FindingSchema>;
export interface Rule {
  id: string;
  version: "1";
  title: string;
  domain: string;
  severity: z.infer<typeof Severity>;
  classification: Finding["classification"];
  confidence: Finding["confidence"];
  observation: string;
  method: string;
  remediation: string[];
  acceptance_tests: string[];
  limitations: string[];
  missing_facts: string[];
  sources: string[];
}
export interface FileRecord {
  path: string;
  text: string;
  hash: string;
}
export const LimitsSchema = z
  .object({
    max_files: z.number().int().min(1).max(10000).default(3000),
    max_file_bytes: z.number().int().min(1).max(1000000).default(500000),
    max_total_bytes: z.number().int().min(1).max(50000000).default(20000000),
    max_duration_ms: z.number().int().min(1).max(120000).default(30000),
    max_findings: z.number().int().min(1).max(2000).default(500),
  })
  .strict();
export const ScanOptionsSchema = z
  .object({
    limits: LimitsSchema.default(() => LimitsSchema.parse({})),
    include_rules: z.array(z.string().max(100)).max(100).optional(),
  })
  .strict();
export type ScanOptions = z.infer<typeof ScanOptionsSchema>;
export interface Scan {
  schema_version: "1";
  id: string;
  created_at: string;
  version: string;
  project_id: string;
  root: string;
  snapshot_hash: string;
  state: "complete" | "partial" | "cancelled";
  files_scanned: number;
  bytes_scanned: number;
  executed_rules: string[];
  omissions: Record<string, number>;
  warnings: string[];
  findings: Finding[];
  limits: z.infer<typeof LimitsSchema>;
  disclaimer: string;
}
export const FactSchema = z
  .object({
    state: z.enum(["known", "unknown", "disputed"]),
    value: z
      .union([
        z.string().max(200),
        z.boolean(),
        z.number().finite(),
        z.array(z.string().max(100)).max(50),
      ])
      .optional(),
  })
  .strict()
  .refine(
    (x) => x.state !== "known" || x.value !== undefined,
    "Known facts require a value",
  );
export const FactsSchema = z
  .object({
    owner_country: FactSchema.optional(),
    target_markets: FactSchema.optional(),
    actual_user_markets: FactSchema.optional(),
    audience: FactSchema.optional(),
    child_directed: FactSchema.optional(),
    known_minor_users: FactSchema.optional(),
    personal_data: FactSchema.optional(),
    sensitive_data: FactSchema.optional(),
    advertising: FactSchema.optional(),
    cross_border_transfers: FactSchema.optional(),
    subscriptions: FactSchema.optional(),
    ugc: FactSchema.optional(),
    ai_features: FactSchema.optional(),
    industries: FactSchema.optional(),
    revenue: FactSchema.optional(),
    entity_role: FactSchema.optional(),
    retention: FactSchema.optional(),
    rights_process: FactSchema.optional(),
    incident_response: FactSchema.optional(),
  })
  .strict();
export type Facts = z.infer<typeof FactsSchema>;
export class SafeError extends Error {
  constructor(
    public code: string,
    message: string,
  ) {
    super(message);
  }
}
export const hashInput = z.string().regex(/^[a-f0-9]{64}$/);
export const idInput = z.string().regex(/^[a-z]+_[a-f0-9]{24}$/);
