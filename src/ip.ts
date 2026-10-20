import parseSPDX from "spdx-expression-parse";
import { z } from "zod";
import { DISCLAIMER } from "./models.js";
import { sha } from "./scanner.js";
import { ipSnapshot, isAsset, type IPSnapshot } from "./ip-files.js";
export const IPInput = z
  .object({
    root: z.string().max(4096),
    brand_terms: z
      .array(
        z
          .string()
          .min(3)
          .max(60)
          .regex(/^[\p{L}\p{N} .'-]+$/u),
      )
      .max(30)
      .default([]),
  })
  .strict();
export interface IPIssue {
  id: string;
  kind: string;
  path: string;
  classification: "needs_human_review";
  observation: string;
  recommendations: string[];
  limitations: string[];
}
export const PROVENANCE_SCHEMA = z
  .object({
    schema_version: z.literal(1),
    assets: z
      .array(
        z
          .object({
            path: z.string().max(1024),
            origin: z.enum([
              "original",
              "third_party",
              "generated",
              "public_domain_claim",
              "unknown",
            ]),
            source_url: z.url().optional(),
            license: z.string().max(200).optional(),
            evidence_reference: z.string().max(300).optional(),
            modifications: z.boolean().optional(),
          })
          .strict(),
      )
      .max(1000),
  })
  .strict();
export const IP_MANUAL_REVIEW = [
  {
    domain: "copyright_and_assets",
    recommendations: [
      "Verify authorship and permission for source, UI copy, illustrations, characters, music, sound, video, models, fonts, maps and datasets.",
      "Check attribution, modification, distribution, commercial-use and sublicensing terms; keep invoices, grant records and source/license versions.",
      "For AI-generated content, review provider terms, source inputs and similarity; do not assume generation grants exclusive rights or cures copied inputs.",
    ],
  },
  {
    domain: "software_licenses",
    recommendations: [
      "Inventory exact direct/transitive dependencies and vendored code; a project LICENSE does not relicense third-party materials.",
      "Review notice/source-offer/copyleft/network-use/patent provisions in the actual distribution/linking context. AND requires combined obligations; OR may offer alternatives.",
      "Inspect license exceptions and conflicts with proprietary distribution, app stores, DRM, hosting, customer contracts and chosen project terms.",
    ],
  },
  {
    domain: "brands_trade_dress_and_publicity",
    recommendations: [
      "Search official trademark registers in relevant countries and goods/services classes, plus relevant unregistered uses; names, logos and domains may conflict despite different spelling.",
      "Review confusingly similar UI/storefront presentation, franchise/character use, endorsements, photographs and personality/likeness permissions.",
      "A textual brand reference may be nominative, commentary or otherwise permitted; it is not an infringement finding.",
    ],
  },
  {
    domain: "patents_designs_and_trade_secrets",
    recommendations: [
      "Obtain qualified freedom-to-operate review where functionality, hardware, game systems, technical inventions or registered designs create risk.",
      "A text/asset match cannot resolve patent claims, validity, territorial scope or patent exhaustion.",
      "Confirm contractors/employees assigned relevant rights and no confidential source, datasets or employer trade secrets were imported.",
    ],
  },
  {
    domain: "ugc_and_platform_duties",
    recommendations: [
      "Review upload licenses, contributor terms, takedown/counter-notice processes, moderation, repeat-abuse handling and jurisdiction-specific intermediary duties.",
      "Separate a platform user’s claim from evidence of permission; preserve review and dispute records.",
    ],
  },
];
function licenses(node: parseSPDX.Info): string[] {
  return "license" in node
    ? [node.license]
    : [...licenses(node.left), ...licenses(node.right)];
}
export function reviewIP(snapshot: IPSnapshot, brandTerms: string[] = []) {
  const issues: IPIssue[] = [];
  let issuesTruncated = false;
  const manifests: {
    path: string;
    license_expression: string | null;
    license_status: string;
    declared_dependencies: number;
  }[] = [];
  const add = (
    kind: string,
    path: string,
    observation: string,
    recommendations: string[],
    limitations: string[],
  ) => {
    if (issues.length >= 300) {
      issuesTruncated = true;
      return;
    }
    issues.push({
      id: "ip_" + sha(kind + "\0" + path).slice(0, 24),
      kind,
      path,
      classification: "needs_human_review",
      observation,
      recommendations,
      limitations,
    });
  };
  const rootLicense = snapshot.files.some((f) =>
    /^(?:LICENSE|LICENCE|COPYING)(?:\.[a-z]+)?$/i.test(f.path),
  );
  const rootTexts = snapshot.files
    .filter((f) => /^(?:LICENSE|LICENCE|COPYING)(?:\.[a-z]+)?$/i.test(f.path))
    .map((f) => f.text ?? "")
    .join("\n");
  const licenseFamilies = [
    ...new Set(
      [
        /Permission is hereby granted,\s+free of charge/i.test(rootTexts)
          ? "MIT"
          : null,
        /Apache License[\s\S]{0,80}Version 2\.0/i.test(rootTexts)
          ? "Apache"
          : null,
        /GNU (?:AFFERO |LESSER )?GENERAL PUBLIC LICENSE/i.test(rootTexts)
          ? "GNU"
          : null,
        /Mozilla Public License[\s\S]{0,80}Version 2\.0/i.test(rootTexts)
          ? "MPL"
          : null,
      ].filter((x): x is string => x !== null),
    ),
  ];

  if (!rootLicense)
    add(
      "project-license-not-observed",
      ".",
      "No root license file was observed. Absence of a license does not grant permission to reuse code.",
      [
        "Confirm ownership and distribution intent; select approved terms and include the full license and required notices.",
      ],
      ["Licensing may be documented outside the scanned files."],
    );
  let provenance: z.infer<typeof PROVENANCE_SCHEMA> | undefined;
  const manifest = snapshot.files.find(
    (f) => f.path === "juriscan.provenance.json",
  );
  if (manifest?.text) {
    try {
      provenance = PROVENANCE_SCHEMA.parse(JSON.parse(manifest.text));
    } catch {
      add(
        "invalid-provenance-manifest",
        manifest.path,
        "The provenance manifest does not match the supported schema.",
        [
          "Validate schema_version 1 and each asset record; do not invent ownership evidence.",
        ],
        ["Invalid metadata is not proof that assets are unlicensed."],
      );
    }
  }
  for (const f of snapshot.files) {
    if (/(?:^|\/)package\.json$/.test(f.path) && f.text) {
      try {
        const p = JSON.parse(f.text);
        const raw = typeof p.license === "string" ? p.license : null;
        let status = "missing",
          expression: string | null = null;
        if (raw) {
          try {
            if (raw.length > 500)
              throw new Error("License expression too long");
            const tree = parseSPDX(raw);
            expression = raw;
            status = "valid_spdx_expression";
            const ids = licenses(tree);
            if (f.path === "package.json" && licenseFamilies.length === 1) {
              const family = (id: string) =>
                /^(?:A?GPL|LGPL)/.test(id) ? "GNU" : id.split("-")[0];
              if (!ids.some((id) => family(id) === licenseFamilies[0]))
                add(
                  "license-metadata-disagreement",
                  f.path,
                  "The root license text resembles a different license family from the package expression.",
                  [
                    "Review whether this is intentional dual licensing, an aggregate notice, or incorrect metadata.",
                    "Align declared project terms and supplied license documents without removing third-party notices.",
                  ],
                  [
                    "Text recognition is heuristic; multiple licenses may legitimately coexist. This does not prove incompatibility.",
                  ],
                );
            }

            if (
              ids.some((id) =>
                /^(?:A?GPL|LGPL|MPL|EPL|CDDL|CPL|OSL|EUPL|CC-BY-SA)/.test(id),
              )
            )
              add(
                "reciprocal-license-review",
                f.path,
                "The declared license expression contains a reciprocal/copyleft-family license.",
                [
                  "Review the exact expression, exceptions and distribution/network-use context with a qualified reviewer.",
                  "Check whether an OR alternative is available; do not assume all branches are mandatory or incompatible.",
                ],
                [
                  "A license family alone does not prove a conflict. Dependency and linking facts are not resolved.",
                ],
              );
            if (ids.some((id) => /^(?:LicenseRef-|DocumentRef-)/.test(id)))
              add(
                "custom-license-review",
                f.path,
                "A custom license reference requires the underlying terms.",
                [
                  "Locate the referenced text and confirm permissions, restrictions and evidence.",
                ],
                ["SPDX syntax validity does not validate rights or terms."],
              );
          } catch {
            status =
              raw === "UNLICENSED"
                ? "explicitly_unlicensed"
                : "non_spdx_or_invalid";
            add(
              "license-terms-review",
              f.path,
              "The package declares non-SPDX, missing-document or no-license terms.",
              [
                "Read the actual terms; a custom notice or UNLICENSED declaration is not permission to redistribute.",
              ],
              ["Custom licensing can be intentional and legitimate."],
            );
          }
        } else
          add(
            "package-license-missing",
            f.path,
            "Package license metadata is absent.",
            [
              "Locate applicable license files and upstream version-specific terms.",
            ],
            [
              "Missing package metadata does not establish absence of a license.",
            ],
          );
        const keys = (value: unknown) =>
          value && typeof value === "object" && !Array.isArray(value)
            ? Object.keys(value)
            : [];
        const deps = new Set([
          ...keys(p.dependencies),
          ...keys(p.devDependencies),
          ...keys(p.optionalDependencies),
        ]);
        manifests.push({
          path: f.path,
          license_expression: expression,
          license_status: status,
          declared_dependencies: deps.size,
        });
        if (deps.size)
          add(
            "dependency-license-inventory",
            f.path,
            "Declared dependencies require version-specific license and attribution review.",
            [
              "Generate/review an SBOM from your trusted lockfile/toolchain and inspect transitive and bundled assets.",
              "Confirm SPDX metadata against distributed license files; this scan does not install or execute dependencies.",
            ],
            [
              "Package declarations alone do not resolve transitive licenses, exceptions, linkage or compatibility.",
            ],
          );
      } catch {
        add(
          "unreadable-package-metadata",
          f.path,
          "Package metadata could not be parsed.",
          ["Repair the metadata or review its original terms manually."],
          ["No licensing conclusion is available."],
        );
      }
    }
    if (
      f.text &&
      /\bCopyright\b|©|SPDX-License-Identifier\s*:/i.test(f.text) &&
      !/(?:^|\/)(?:LICENSE|LICENCE|COPYING|NOTICE)(?:\.|$)/i.test(f.path)
    )
      add(
        "third-party-notice-review",
        f.path,
        "A copyright or SPDX marker appears in this file.",
        [
          "Inspect the notice in context, verify its owner/source/version and preserve required attribution.",
          "A copied notice is not itself permission or proof of original authorship.",
        ],
        [
          "The marker may refer to this project, a quoted example or permitted reuse. No holder names or source excerpts are returned.",
        ],
      );
    if (isAsset(f.path)) {
      const record = provenance?.assets.find((a) => a.path === f.path);
      if (!record || record.origin === "unknown" || !record.evidence_reference)
        add(
          "asset-provenance-gap",
          f.path,
          "No complete asset provenance declaration was found.",
          [
            "Record original authorship/assignment or licensed source, version, permissions, modifications and evidence reference.",
            "For fonts, music, models and stock assets, check web/app/game embedding and redistribution restrictions.",
          ],
          [
            "Absence of local records is not proof of infringement. A declaration still needs independent verification.",
          ],
        );
      else
        add(
          "asset-provenance-declared",
          f.path,
          "An asset provenance declaration exists but has not been verified.",
          [
            "Check the referenced evidence and permission scope before release.",
          ],
          [
            "User-declared original, generated or public-domain status does not prove rights.",
          ],
        );
    }
    if (
      f.text &&
      brandTerms.some((term) =>
        f.text!.toLocaleLowerCase("en").includes(term.toLocaleLowerCase("en")),
      )
    )
      add(
        "brand-term-reference",
        f.path,
        "One or more user-selected brand terms occur in this file.",
        [
          "Inspect whether this is a product name, logo/character reference, integration, commentary or permitted attribution.",
          "Perform jurisdiction/class-specific trademark and trade-dress review; compare the actual presentation and user-confusion risk.",
        ],
        [
          "Substring occurrence is only a review lead, not registration, similarity or infringement proof.",
        ],
      );
  }
  return {
    schema_version: "1",
    state:
      issuesTruncated && snapshot.state === "complete"
        ? "partial"
        : snapshot.state,
    issues_truncated: issuesTruncated,
    files_reviewed: snapshot.files.length,
    bytes_reviewed: snapshot.bytes,
    omissions: snapshot.omissions,
    project_license_file_observed: rootLicense,
    package_manifests: manifests,
    issues,
    manual_review: IP_MANUAL_REVIEW,
    legal_status: "not_assessed",
    web_search_performed: false,
    limitations: [
      "No exhaustive internet, trademark, patent or copyright registry search.",
      "No legal determination of ownership, fair use, substantial similarity, exceptions, enforceability or license compatibility.",
      "Dependency declarations and selected files are inspected; node_modules and generated output are excluded.",
    ],
    disclaimer: DISCLAIMER,
  };
}
export async function ipReview(
  root: string,
  allowed: string[],
  brands: string[] = [],
  signal?: AbortSignal,
) {
  return reviewIP(await ipSnapshot(root, allowed, signal), brands);
}
