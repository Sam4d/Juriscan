# Benchmarks and evaluation

The detector regression set has 12 detectors × 3 positive, 3 negative and 1 ambiguous case: 36 positive, 36 negative and 12 ambiguous labeled examples. The passing regression run correctly triggers the target detector for all positive examples and leaves that detector unasserted for all negative/ambiguous examples. This is a small, authored regression set; no statistically meaningful real-world precision/recall or legal-accuracy claim follows.

The combined vulnerable fixture produces 12 findings and its negative counterpart produces zero for this detector set. Neither fixture is a complete application, and “negative” does not mean secure or compliant. No expert-approved legal applicability benchmark exists; all statutory applicability is unknown.

Run `pnpm build` then `node scripts/benchmark.mjs` for a separate single-process runtime measurement on 1,000 generated trivial TypeScript files. The observed result, date, Node version, bytes, duration and peak RSS are in [benchmark-result.json](benchmark-result.json). The benchmark cleans up its temporary directory. It is not a large-monorepo, worst-case parser or production throughput guarantee.
