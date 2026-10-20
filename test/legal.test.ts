import { it, expect } from "vitest";
import {
  CATALOG,
  intake,
  applicability,
  industryChecklist,
  INDUSTRIES,
} from "../src/legal.js";
it("all legal records remain research candidates with zero legally reviewed coverage", () => {
  expect(CATALOG.verified_active).toBe(0);
  expect(new Set(CATALOG.entries.map((l) => l.id)).size).toBe(
    CATALOG.entries.length,
  );
  for (const law of CATALOG.entries) {
    expect(law.review_status).toBe("research_preview");
    expect(law.source_checked_at).toBeNull();
    expect(law.reviewer).toBeNull();
    expect(law.supported_controls).toEqual([]);
  }
});
it("missing and disputed facts stay unknown and user input is not legal proof", () => {
  const a = intake({ child_directed: { state: "disputed" } });
  expect(a.questions.some((q) => q.field === "child_directed")).toBe(true);
  const b = applicability(
    { target_markets: { state: "known", value: ["EU"] } },
    ["EU", "ZZ"],
  );
  expect(b.candidates.every((c) => c.status === "unknown")).toBe(true);
  expect(b.candidates[1]!.frameworks).toEqual([]);
  expect(() => intake({ revenue: { state: "known" } })).toThrow();
  expect(() => intake({ invented: "value" })).toThrow();
});
it("distinguishes standards and attestation from laws", () => {
  expect(CATALOG.entries.find((l) => l.name === "WCAG 2.2")!.kind).toBe(
    "standard",
  );
  expect(CATALOG.entries.find((l) => l.name === "SOC 2")!.kind).toBe(
    "attestation_framework",
  );
});
it("industry/feature combinations compose recommendations and surface missing jurisdictions", () => {
  const r = industryChecklist({
    industries: ["healthcare", "education"],
    features: ["ai", "subscriptions"],
    jurisdictions: ["EU", "ZZ"],
  });
  expect(r.recommendations.map((r) => r.domain)).toEqual(
    expect.arrayContaining([
      "health",
      "children",
      "education",
      "ai",
      "payments",
    ]),
  );
  expect(
    r.coverage_gaps.find((g) => g.jurisdiction === "ZZ")!.inventory_entries,
  ).toBe(0);
  expect(r.exhaustive).toBe(false);
  expect(
    r.recommendations.every((r) => r.automation === "manual_review_required"),
  ).toBe(true);
});
it("all listed sectors yield scoped review questions", () => {
  for (const industry of Object.keys(INDUSTRIES)) {
    const r = industryChecklist({
      industries: [industry],
      jurisdictions: ["GLOBAL"],
    });
    expect(r.recommendations.length).toBeGreaterThanOrEqual(3);
    expect(r.coverage_gaps[0]!.verified_obligations).toBe(0);
  }
});
it("invalid taxonomy choices fail instead of silently dropping sectors", () =>
  expect(() =>
    industryChecklist({ industries: ["made-up"], jurisdictions: ["EU"] }),
  ).toThrow());
