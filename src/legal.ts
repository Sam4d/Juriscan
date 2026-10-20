import { readFileSync } from "node:fs";
import { z } from "zod";
import { FactsSchema, DISCLAIMER, type Facts } from "./models.js";
export const LawSchema = z
  .object({
    id: z.string(),
    jurisdiction: z.string(),
    name: z.string(),
    kind: z.enum([
      "law",
      "regulation",
      "directive",
      "research_topic",
      "statutory_code",
      "standard",
      "industry_standard",
      "attestation_framework",
      "treaty",
    ]),
    primary_source: z.url().nullable(),
    section: z.string().nullable(),
    domains: z.array(z.string()),
    review_status: z.literal("research_preview"),
    legal_status: z.literal("unverified"),
    effective_date: z.null(),
    source_checked_at: z.null(),
    reviewer: z.null(),
    supported_controls: z.array(z.string()).max(0),
    unsupported_obligations: z.array(z.string()),
    next_review_date: z.null(),
  })
  .strict();
const catalogSchema = z
  .object({
    schema_version: z.literal(1),
    exhaustive: z.literal(false),
    verified_active: z.literal(0),
    entries: z.array(LawSchema),
  })
  .strict();
export const CATALOG = catalogSchema.parse(
  JSON.parse(
    readFileSync(
      new URL("../source-registry/laws.json", import.meta.url),
      "utf8",
    ),
  ),
);
export type Law = z.infer<typeof LawSchema>;
export const INDUSTRIES: Record<string, string[]> = {
  "general-saas": ["privacy", "consumer", "security", "accessibility"],
  healthcare: ["health", "privacy", "security", "accessibility"],
  "mental-health": ["health", "children", "privacy"],
  pharmacy: ["health", "consumer"],
  finance: ["finance", "privacy", "security"],
  insurance: ["finance", "health", "consumer"],
  "credit-lending": ["finance", "consumer", "employment"],
  crypto: ["finance", "consumer"],
  education: ["education", "children", "privacy", "accessibility"],
  childcare: ["children", "privacy"],
  "employment-recruiting": ["employment", "ai", "privacy"],
  "hr-payroll": ["employment", "finance", "privacy"],
  "legal-services": ["professional", "privacy", "security"],
  government: ["public-sector", "accessibility", "security"],
  ecommerce: ["consumer", "payments", "marketing"],
  marketplace: ["platforms", "consumer", "payments"],
  "social-network": ["platforms", "children", "privacy"],
  dating: ["platforms", "privacy", "children"],
  gaming: ["children", "consumer", "ip"],
  gambling: ["gambling", "finance", "children"],
  "media-streaming": ["media", "ip", "privacy"],
  "news-publishing": ["media", "ip", "platforms"],
  "creator-platform": ["platforms", "ip", "payments"],
  advertising: ["marketing", "tracking", "privacy"],
  travel: ["travel", "consumer", "privacy"],
  hospitality: ["travel", "consumer", "payments"],
  "real-estate": ["housing", "finance", "privacy"],
  "property-management": ["housing", "privacy", "payments"],
  transport: ["transport", "location", "consumer"],
  logistics: ["transport", "location", "employment"],
  "food-delivery": ["food", "transport", "consumer"],
  restaurants: ["food", "consumer", "payments"],
  agriculture: ["agriculture", "environment", "iot"],
  manufacturing: ["product-safety", "iot", "employment"],
  construction: ["product-safety", "housing", "employment"],
  energy: ["energy", "environment", "security"],
  utilities: ["energy", "public-sector", "security"],
  telecom: ["telecom", "privacy", "security"],
  "iot-smart-home": ["iot", "privacy", "security"],
  cybersecurity: ["security", "privacy"],
  "ai-developer-tools": ["ai", "ip", "privacy"],
  biometrics: ["biometrics", "privacy", "security"],
  "fitness-wellness": ["health", "consumer", "privacy"],
  "sports-events": ["consumer", "children", "payments"],
  "charity-nonprofit": ["fundraising", "privacy", "payments"],
  "religious-community": ["privacy", "children"],
  "political-campaign": ["elections", "marketing", "privacy"],
  "adult-content": ["adult", "children", "platforms"],
  "weapons-controlled-goods": ["controlled-goods", "consumer"],
  "alcohol-tobacco": ["controlled-goods", "children"],
  "scientific-research": ["research", "health", "privacy"],
  "environmental-services": ["environment", "public-sector"],
  "professional-services": ["professional", "privacy", "consumer"],
  other: ["unclassified"],
};
export const FEATURES: Record<string, string[]> = {
  accounts: ["privacy", "security"],
  subscriptions: ["payments", "consumer"],
  checkout: ["payments", "consumer"],
  analytics: ["tracking", "privacy"],
  advertising: ["marketing", "tracking"],
  children: ["children"],
  "user-content": ["platforms", "ip"],
  messaging: ["platforms", "privacy"],
  ai: ["ai", "ip", "privacy"],
  health: ["health", "privacy"],
  biometrics: ["biometrics", "privacy"],
  geolocation: ["location", "privacy"],
  "email-marketing": ["marketing"],
  sms: ["marketing", "telecom"],
  "cross-border": ["privacy", "localization"],
  "public-services": ["public-sector", "accessibility"],
  "file-uploads": ["security", "ip"],
  "credit-scoring": ["finance", "ai"],
  "employment-decisions": ["employment", "ai"],
  "physical-products": ["product-safety", "consumer"],
  "connected-device": ["iot", "security"],
  donations: ["fundraising", "payments"],
  "video-streaming": ["media", "ip"],
  "data-broker": ["privacy", "marketing"],
  "third-party-vendors": ["privacy", "security"],
  "open-source-distribution": ["ip", "security"],
  "marketplace-payouts": ["finance", "payments"],
};
export const ARCHETYPES = [
  "marketing-site",
  "blog",
  "directory",
  "booking",
  "ecommerce",
  "marketplace",
  "subscription-saas",
  "internal-dashboard",
  "crm",
  "community",
  "chat",
  "social-network",
  "mobile-backend",
  "developer-api",
  "ai-assistant",
  "content-platform",
  "learning-platform",
  "telehealth",
  "fintech",
  "iot-control",
  "public-service",
  "other",
];
export const DOMAIN_GUIDANCE: Record<string, string> = {
  privacy:
    "Map data, purposes, lawful processing conditions, notices, rights, retention, vendors and transfers; verify market-specific thresholds and exemptions.",
  security:
    "Test access control, secrets, encryption, incident handling and deployed configurations using synthetic data.",
  children:
    "Confirm actual ages and intended audience; review local age thresholds, assurance, guardian authorization and child-appropriate design.",
  consumer:
    "Review pricing, claims, disclosures, refunds, unfair terms and consumer redress for the applicable market.",
  payments:
    "Review payment roles, recurring terms, renewal notices, cancellation, refunds, signature verification and duplicate-event handling.",
  tracking:
    "Inventory recipients and purposes; test request/storage behavior before choice, after refusal and after revocation where applicable.",
  accessibility:
    "Test semantic controls, keyboard access, screen readers, contrast and applicable service-specific duties.",
  marketing:
    "Review opt-in/opt-out, message classification, sender identification, suppression lists and campaign records.",
  platforms:
    "Classify hosting/marketplace/social functions; review moderation, reporting, appeals, transparency and minors-related duties.",
  ai: "Classify system and actor roles; evaluate prohibited/high-risk uses, training data rights, transparency and human oversight under current local law.",
  health:
    "Identify clinical versus wellness claims, regulated entity roles, medical-device scope and health-data obligations.",
  finance:
    "Identify regulated activities, licenses, AML/KYC, disclosures, safeguarding, credit reporting and outsourcing duties.",
  education:
    "Determine school relationships, student-record roles, accessibility, minors and contract requirements.",
  employment:
    "Review recruitment discrimination, monitoring, payroll, worker classification and automated employment decisions.",
  ip: "Review copyright, trademarks, database rights, third-party licenses, user-content rights and takedown procedures.",
  biometrics:
    "Distinguish biometric identification templates from ordinary images; review notice, authorization, retention and restrictions.",
  location:
    "Determine precision, retention, user risk, minors and recipients of location data.",
  localization:
    "Check sector and country-specific residency, cross-border transfer mechanisms and governmental access.",
  iot: "Review connected-product safety/security, updates, user information and manufacturer duties.",
  unclassified:
    "Obtain sector classification and qualified local advice; no specialized coverage is available.",
};
const Questions: Record<keyof Facts, string> = {
  owner_country: "Where is the responsible entity established?",
  target_markets: "Which markets are intentionally served?",
  actual_user_markets: "Where are actual users located?",
  audience: "What ages are intended and actually served?",
  child_directed: "Is any service directed to children?",
  known_minor_users: "Are minors known to use the service?",
  personal_data: "What personal data is processed and for which purposes?",
  sensitive_data:
    "Is sensitive, health, biometric or financial data processed?",
  advertising: "Is data used for advertising, sharing or sale?",
  cross_border_transfers:
    "Which transfers, vendors and locations are involved?",
  subscriptions: "Are recurring payments or trials offered?",
  ugc: "Can users publish content or send messages?",
  ai_features: "Which AI systems and actor roles are involved?",
  industries: "Which industries and regulated activities are involved?",
  revenue: "Which entity size and revenue thresholds are met?",
  entity_role: "What legal role, customer relationship and exemptions apply?",
  retention: "What are actual retention and deletion practices?",
  rights_process: "How are rights requests handled and evidenced?",
  incident_response: "Who handles incidents and notification decisions?",
};
export function intake(input: unknown) {
  const facts = FactsSchema.parse(input);
  return {
    facts: Object.fromEntries(
      Object.keys(Questions).map((k) => [
        k,
        facts[k as keyof Facts] ?? { state: "unknown" },
      ]),
    ),
    provenance: "user_supplied_not_verified",
    questions: Object.entries(Questions)
      .filter(([k]) => facts[k as keyof Facts]?.state !== "known")
      .map(([field, question]) => ({ field, question })),
    disclaimer: DISCLAIMER,
  };
}
export function applicability(facts: unknown, jurisdictions: string[]) {
  const normalized = intake(facts);
  return {
    assessment_status: "research_only",
    facts: normalized,
    candidates: jurisdictions.map((j) => ({
      jurisdiction: j,
      status: "unknown",
      legal_review_required: true,
      reason:
        "No reviewed effective-date or legal applicability predicates are shipped. Market selection narrows research; it does not establish territorial scope.",
      frameworks: CATALOG.entries.filter((e) => e.jurisdiction === j),
      missing_facts: normalized.questions,
    })),
    disclaimer: DISCLAIMER,
  };
}
export const IndustryInput = z
  .object({
    industries: z
      .array(z.enum(Object.keys(INDUSTRIES) as [string, ...string[]]))
      .min(1)
      .max(10),
    features: z
      .array(z.enum(Object.keys(FEATURES) as [string, ...string[]]))
      .max(30)
      .default([]),
    archetypes: z
      .array(z.enum(ARCHETYPES as [string, ...string[]]))
      .max(10)
      .default([]),
    jurisdictions: z
      .array(z.string().regex(/^[A-Z]{2,6}(?:-[A-Z0-9]{1,8})?$/))
      .min(1)
      .max(30),
  })
  .strict();
export function industryChecklist(input: unknown) {
  const p = IndustryInput.parse(input);
  const domains = [
    ...new Set([
      "privacy",
      "security",
      "accessibility",
      ...p.industries.flatMap((i) => INDUSTRIES[i]!),
      ...p.features.flatMap((f) => FEATURES[f]!),
    ]),
  ].sort();
  return {
    scope: p,
    exhaustive: false,
    legal_status: "not_assessed",
    recommendations: domains.map((domain) => ({
      domain,
      automation: "manual_review_required",
      recommendation:
        DOMAIN_GUIDANCE[domain] ??
        `Obtain specialist review of ${domain} licensing, duties, contracts and market-specific requirements. No specialized legal pack is implemented.`,
      research_candidates: CATALOG.entries
        .filter(
          (l) =>
            (p.jurisdictions.includes(l.jurisdiction) ||
              l.jurisdiction === "GLOBAL") &&
            l.domains.includes(domain),
        )
        .map((l) => ({
          id: l.id,
          name: l.name,
          source: l.primary_source,
          review_status: l.review_status,
        })),
    })),
    coverage_gaps: p.jurisdictions.map((j) => ({
      jurisdiction: j,
      verified_obligations: 0,
      inventory_entries: CATALOG.entries.filter((l) => l.jurisdiction === j)
        .length,
      action:
        "Research federal/national, regional, municipal, sector, contract, licensing, tax, trade and court-status requirements; no completeness inferred.",
    })),
    combination_policy:
      "Union of selected sector and feature questions. Interactions and conflicting duties require human review. Unlisted industries use other; arbitrary jurisdiction codes yield visible gaps.",
    disclaimer: DISCLAIMER,
  };
}
