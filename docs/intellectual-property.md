# Copyright, intellectual property and web references

Juriscan supplies **review leads, not infringement verdicts or legal clearance**. Copyright ownership, trademark confusion, trade dress, substantial similarity, fair use/fair dealing, public-domain status, patent claims, licensing and publicity rights depend on facts and jurisdiction-specific law that a scanner cannot establish.

## Offline IP review

```sh
node dist/cli.js ip-review --root fixtures/secure
node dist/cli.js ip-review --root /absolute/your/project --brands ExampleBrand,AnotherBrand
```

The corresponding MCP tool is `juriscan_ip_review`. It reads only the authorized project and never accesses the network. Review outputs cover:

- Missing project license files and missing/invalid/custom package license expressions.
- Possible disagreement between recognizable root license text and package metadata.
- Reciprocal/copyleft-family terms that need distribution, linking, network-use and exception analysis. An `OR` alternative is not treated as mandatory simultaneous obligations.
- Declared dependencies that need a real version-specific/transitive license inventory; dependencies are not installed or executed.
- Copyright/SPDX notices that require provenance and attribution review, without returning holder names or source excerpts.
- Assets without provenance evidence: images, SVGs, fonts, audio, video and 3D models, within resource limits.
- User-selected brand-term occurrences. Matching a string does not prove a registered right, confusion or an unauthorized use.

All issues are `needs_human_review`; none is a proven conflict. Generic manual recommendations cover copyright, distribution rights, commercial/embedding terms, generated content, trademarks, trade dress, personality/likeness, patents/designs, trade secrets, contributor assignments and UGC takedown procedures. The catalog adds primary-source research pointers for these domains; they remain unverified.

The reader supports up to 1,000 selected files, 1 MB/file, 20 MB total, 10,000 directory entries, depth 30 and a cooperative 30-second limit. Symlinks, unreadable/oversized supported files and exhausted limits make the review partial. Common dependency/build directories are excluded. Reports cap issues at 300; truncation is explicit. Missing evidence is not evidence of infringement.

## Asset provenance declarations

An optional root `juriscan.provenance.json` records **claims that still require verification**:

```json
{
  "schema_version": 1,
  "assets": [
    {
      "path": "assets/hero.svg",
      "origin": "original",
      "evidence_reference": "Internal contributor assignment record",
      "modifications": false
    }
  ]
}
```

Allowed origins: `original`, `third_party`, `generated`, `public_domain_claim`, `unknown`. Optional fields include `source_url` and `license`. Keep private invoices/contracts outside the public repository; use a non-sensitive reference. Nothing referenced by this manifest is automatically fetched or opened. A manifest cannot prove ownership or suppress legal review. Invalid/incomplete declarations leave provenance gaps visible.

## Explicit web-reference comparison

```sh
node dist/cli.js ip-web --root fixtures/secure --reference-url https://raw.githubusercontent.com/microsoft/TypeScript/main/LICENSE.txt --allow-domain raw.githubusercontent.com --authorize-network
```

For MCP use `juriscan_ip_web_compare` with `root`, `reference_urls`, exact `allowed_domains`, and `authorized_network: true`. The host should obtain the user's approval for the reference set first. There is no network activity in ordinary `scan` or `ip-review` calls. Source code, asset bytes, hashes and search terms are **not uploaded**; only approved reference URLs are fetched with GET.

This is **not whole-web search**. It does not discover candidate URLs, crawl links, use a search engine, log in, bypass paywalls, solve challenges or follow redirects. Supply reference URLs from your own provenance investigation, official register searches or independently authorized searches. Competitor content may be relevant evidence, but a competitor URL is not permission to copy its material.

Exact byte hashes and bounded five-token text-shingle overlap produce review candidates. At most 200 local files and 8,000 tokens per text file are compared against up to 10 supplied references. Text overlap requires at least 30 shared shingles and 60% overlap of the smaller sampled set, with at least 40 unique shingles on each side. These are engineering heuristics, not legal substantial-similarity thresholds. Exact matches require at least 128 bytes. Results cap at 200 matches; truncation is partial. Reported ratios describe sampled text only, never legal risk or clearance.

A live validation fetched Microsoft's public Apache license text and identified the shared license boilerplate in this repository. Byte identity was observed before local line-ending normalization; text overlap remains the appropriate match after normalization. That is expected shared boilerplate, **not an infringement finding**. The negative fixture had no match against that same reference. This exercise verifies transport/comparison, not internet coverage.

## Network trust boundary

References require HTTPS on port 443, exact approved domains, no URL credentials/query/fragment, no cookies or authorization headers, no redirects and no compressed bodies. Each response is capped at 1 MB and ten seconds; the reference phase has a 30-second budget. No browser renders the response, and scripts/links in fetched content do not execute.

For arbitrary approved domains, DNS must resolve to public IPv4 addresses, all answers are checked, and the selected address is pinned while TLS verifies the original hostname. Private/reserved/loopback addresses and IPv6 are refused. This alpha cannot use arbitrary proxy-resolved targets safely.

A configured operator HTTPS proxy may instead serve a fixed public-provider set: `raw.githubusercontent.com`, `www.copyright.gov`, `www.uspto.gov`, `www.wipo.int`, `spdx.org`, `opensource.org`, and `upload.wikimedia.org`. The caller must still explicitly allow the exact domain. The proxy and these providers' DNS/egress are trusted in this mode; it is not described as locally DNS-pinned. TLS verification remains enabled. The route is reported. If a route is unavailable, results remain partial; the scanner does not weaken address checks to force a successful response.

## What still needs specialist review

No visual/perceptual image search, logo classifier, audio fingerprinting, reverse-image engine, registered-design/patent claim search, trademark-register search or complete third-party code index is implemented. Transformed/obfuscated copies, inaccessible/deleted pages and unindexed material can be missed. Common boilerplate can match. No match never means no conflict.

For app/game releases, obtain evidence of art/music/font/model/data licenses and contributor assignments; review franchise characters/names, store icons, game UI presentation and publicity rights. Search official trademark registers in the actual markets and goods/services classes. Obtain freedom-to-operate advice for relevant patent/design exposure. Review app-store/customer-contract obligations against actual third-party terms. Public-domain and generated-content claims need evidence and jurisdiction-specific review.

Disclaimers and Apache-2.0 do not eliminate liability for unauthorized content or misleading assurances. Juriscan cannot give a comprehensive legal opinion on these matters.
