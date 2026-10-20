import https from "node:https";
import { lookup } from "node:dns/promises";
import { BlockList, isIP } from "node:net";
import { createHash } from "node:crypto";
import { z } from "zod";
import { SafeError, DISCLAIMER } from "./models.js";
import { ipSnapshot, type IPSnapshot } from "./ip-files.js";
export const WebIPInput = z
  .object({
    root: z.string().max(4096),
    reference_urls: z.array(z.url().max(2048)).min(1).max(10),
    allowed_domains: z
      .array(
        z.string().regex(/^(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,63}$/),
      )
      .min(1)
      .max(10),
    authorized_network: z.literal(true),
  })
  .strict();
const forbidden = new BlockList();
for (const [network, bits] of [
  ["0.0.0.0", 8],
  ["10.0.0.0", 8],
  ["100.64.0.0", 10],
  ["127.0.0.0", 8],
  ["169.254.0.0", 16],
  ["172.16.0.0", 12],
  ["192.0.0.0", 24],
  ["192.0.2.0", 24],
  ["192.88.99.0", 24],
  ["192.168.0.0", 16],
  ["198.18.0.0", 15],
  ["198.51.100.0", 24],
  ["203.0.113.0", 24],
  ["224.0.0.0", 4],
  ["240.0.0.0", 4],
] as const)
  forbidden.addSubnet(network, bits, "ipv4");
export function validatePublicAddresses(addresses: string[]) {
  if (
    !addresses.length ||
    addresses.some((ip) => isIP(ip) !== 4 || forbidden.check(ip, "ipv4"))
  )
    throw new SafeError(
      "REFERENCE_ADDRESS_DENIED",
      "Only resolved public IPv4 addresses are supported; private, reserved and IPv6 addresses are denied.",
    );
  return addresses[0]!;
}
export function validateReference(url: string, domains: string[]) {
  let u: URL;
  try {
    u = new URL(url);
  } catch {
    throw new SafeError("REFERENCE_URL_DENIED", "Invalid reference URL.");
  }
  if (
    u.protocol !== "https:" ||
    u.username ||
    u.password ||
    (u.port && u.port !== "443") ||
    u.search ||
    u.hash ||
    isIP(u.hostname) ||
    !domains.includes(u.hostname) ||
    !u.hostname.includes(".") ||
    /\.(?:local|internal|localhost|test|invalid|lan|home)$/.test(u.hostname)
  )
    throw new SafeError(
      "REFERENCE_URL_DENIED",
      "References require exact approved public domains, HTTPS on port 443, and no credentials, query strings or fragments.",
    );
  return u;
}
export const CURATED_PROXY_HOSTS = new Set([
  "raw.githubusercontent.com",
  "www.copyright.gov",
  "www.uspto.gov",
  "www.wipo.int",
  "spdx.org",
  "opensource.org",
  "upload.wikimedia.org",
]);
export interface PublicReference {
  url: string;
  sha256: string;
  bytes: number;
  text?: string;
  content_type: string;
  network_route?: string;
}
export async function fetchPublicReference(
  raw: string,
  domains: string[],
  signal?: AbortSignal,
): Promise<PublicReference> {
  const u = validateReference(raw, domains);
  // Arbitrary approved hosts use public-address-pinned direct HTTPS. A configured operator
  // proxy is permitted only for this fixed list of public reference providers; no redirects.
  const proxy =
    CURATED_PROXY_HOSTS.has(u.hostname) &&
    Boolean(process.env.HTTPS_PROXY || process.env.https_proxy);
  let address: string | undefined;
  if (!proxy) {
    const resolve = lookup(u.hostname, { all: true, family: 4 });
    let timer: ReturnType<typeof setTimeout> | undefined;
    const records = await Promise.race([
      resolve,
      new Promise<never>((_, reject) => {
        timer = setTimeout(
          () =>
            reject(
              new SafeError(
                "REFERENCE_UNAVAILABLE",
                "Reference DNS lookup timed out.",
              ),
            ),
          5000,
        );
      }),
    ]).finally(() => clearTimeout(timer));
    address = validatePublicAddresses(records.map((r) => r.address));
  }
  if (signal?.aborted)
    throw new SafeError("CANCELLED", "Reference comparison was cancelled.");
  const agent = new https.Agent({
    keepAlive: false,
    maxSockets: 1,
    proxyEnv: proxy
      ? {
          HTTPS_PROXY: process.env.HTTPS_PROXY ?? process.env.https_proxy,
          NO_PROXY: "",
        }
      : {},
  });
  try {
    return await new Promise<PublicReference>((resolve, reject) => {
      let settled = false;
      const finish = (error?: Error, result?: PublicReference) => {
        if (settled) return;
        settled = true;
        clearTimeout(deadline);
        if (error) reject(error);
        else resolve(result!);
      };
      const request = https.request(
        u,
        {
          method: "GET",
          rejectUnauthorized: true,
          family: 4,
          agent,
          signal,
          servername: u.hostname,
          ...(!proxy
            ? {
                lookup: (
                  _hostname: string,
                  _options: unknown,
                  callback: (
                    error: Error | null,
                    address: string,
                    family: number,
                  ) => void,
                ) => callback(null, address!, 4),
              }
            : {}),
          headers: {
            "User-Agent": "Juriscan-public-reference-review/0.1",
            "Accept-Encoding": "identity",
            Accept:
              "text/plain,text/html,application/json,image/*;q=0.8,*/*;q=0.1",
          },
        },
        (response) => {
          if (response.statusCode !== 200) {
            response.destroy();
            finish(
              new SafeError(
                "REFERENCE_UNAVAILABLE",
                "Reference did not return HTTP 200. Redirects and authentication are not followed.",
              ),
            );
            return;
          }
          if (
            response.headers["content-encoding"] &&
            response.headers["content-encoding"] !== "identity"
          ) {
            response.destroy();
            finish(
              new SafeError(
                "REFERENCE_ENCODING_DENIED",
                "Compressed reference responses are not accepted.",
              ),
            );
            return;
          }
          const length = Number(response.headers["content-length"] ?? 0);
          if (length > 1000000) {
            response.destroy();
            finish(
              new SafeError(
                "REFERENCE_TOO_LARGE",
                "Reference exceeds the 1 MB cap.",
              ),
            );
            return;
          }
          const chunks: Buffer[] = [];
          let total = 0;
          response.on("data", (chunk: Buffer) => {
            total += chunk.length;
            if (total > 1000000) {
              response.destroy();
              finish(
                new SafeError(
                  "REFERENCE_TOO_LARGE",
                  "Reference exceeds the 1 MB cap.",
                ),
              );
              return;
            }
            chunks.push(chunk);
          });
          response.on("error", () =>
            finish(
              new SafeError(
                "REFERENCE_UNAVAILABLE",
                "Reference could not be read securely.",
              ),
            ),
          );
          response.on("end", () => {
            const body = Buffer.concat(chunks);
            const type = String(
              response.headers["content-type"] ?? "application/octet-stream",
            );
            const result: PublicReference = {
              url: u.href,
              sha256: createHash("sha256").update(body).digest("hex"),
              bytes: body.length,
              content_type: type,
              network_route: proxy
                ? "operator_proxy_curated_host"
                : "direct_public_ipv4_pinned",
            };
            if (
              (/^text\//.test(type) || /json|javascript|svg\+xml/.test(type)) &&
              !body.includes(0)
            )
              result.text = body.toString("utf8");
            finish(undefined, result);
          });
        },
      );
      const deadline = setTimeout(() => {
        request.destroy();
        finish(
          new SafeError(
            "REFERENCE_UNAVAILABLE",
            "Reference request timed out.",
          ),
        );
      }, 10000);
      request.on("error", () =>
        finish(
          new SafeError(
            signal?.aborted ? "CANCELLED" : "REFERENCE_UNAVAILABLE",
            "Reference unavailable through the secure direct HTTPS route.",
          ),
        ),
      );
      request.end();
    });
  } finally {
    agent.destroy();
  }
}
function shingles(text: string): Set<string> {
  const words =
    text
      .toLowerCase()
      .match(/[\p{L}\p{N}_]{2,}/gu)
      ?.slice(0, 8000) ?? [];
  const out = new Set<string>();
  for (let i = 0; i + 5 <= words.length; i++)
    out.add(
      createHash("sha256")
        .update(words.slice(i, i + 5).join(" "))
        .digest("hex")
        .slice(0, 24),
    );
  return out;
}
export function compareReferences(
  snapshot: IPSnapshot,
  references: PublicReference[],
) {
  const matches: {
    path: string;
    reference_url: string;
    kind: string;
    shared_shingles?: number;
    overlap_of_smaller_sample?: number;
    classification: string;
    recommendations: string[];
  }[] = [];
  const remoteSamples = references.map((reference) => ({
    reference,
    sample: reference.text ? shingles(reference.text) : new Set<string>(),
  }));
  for (const file of snapshot.files.slice(0, 200)) {
    const item = {
      file,
      shingles: file.text ? shingles(file.text) : new Set<string>(),
    };
    for (const { reference, sample: remote } of remoteSamples) {
      let kind: string | undefined,
        shared = 0,
        ratio = 0;
      if (
        item.file.bytes >= 128 &&
        reference.bytes >= 128 &&
        item.file.hash === reference.sha256
      )
        kind = "exact_byte_match";
      else if (item.shingles.size >= 40 && remote.size >= 40) {
        for (const h of item.shingles) if (remote.has(h)) shared++;
        ratio = shared / Math.min(item.shingles.size, remote.size);
        if (shared >= 30 && ratio >= 0.6) kind = "text_overlap_candidate";
      }
      if (kind) {
        matches.push({
          path: item.file.path,
          reference_url: reference.url,
          kind,
          ...(kind === "text_overlap_candidate"
            ? {
                shared_shingles: shared,
                overlap_of_smaller_sample: Math.round(ratio * 100) / 100,
              }
            : {}),
          classification: "needs_human_review",
          recommendations: [
            "Check author/source history, license grant, attribution, modification and distribution rights.",
            "Determine whether common boilerplate, shared upstream material, public-domain status or an applicable exception explains the match.",
            "Obtain qualified advice before concluding infringement or making a removal demand.",
          ],
        });
        if (matches.length >= 200) return { matches, truncated: true };
      }
    }
  }
  return { matches, truncated: snapshot.files.length > 200 };
}
export async function ipWebReview(
  input: unknown,
  allowedRoots: string[],
  signal?: AbortSignal,
) {
  const p = WebIPInput.parse(input);
  for (const url of p.reference_urls) validateReference(url, p.allowed_domains);
  const snapshot = await ipSnapshot(p.root, allowedRoots, signal),
    references: PublicReference[] = [],
    unavailable: { url: string; code: string }[] = [];
  const controller = new AbortController(),
    deadline = setTimeout(() => controller.abort(), 30000);
  const combined = signal
    ? AbortSignal.any([signal, controller.signal])
    : controller.signal;
  try {
    for (const url of p.reference_urls) {
      if (combined.aborted) {
        unavailable.push({ url, code: "CANCELLED_OR_TIME_LIMIT" });
        continue;
      }
      try {
        references.push(
          await fetchPublicReference(url, p.allowed_domains, combined),
        );
      } catch (error) {
        unavailable.push({
          url,
          code:
            error instanceof SafeError ? error.code : "REFERENCE_UNAVAILABLE",
        });
      }
    }
  } finally {
    clearTimeout(deadline);
  }
  const comparison = compareReferences(snapshot, references);
  return {
    state:
      snapshot.state === "complete" &&
      !unavailable.length &&
      !comparison.truncated
        ? "complete"
        : "partial",
    local_files: snapshot.files.length,
    local_omissions: snapshot.omissions,
    reference_results: references.map(
      ({ text: _text, ...metadata }) => metadata,
    ),
    unavailable,
    ...comparison,
    legal_status: "not_assessed",
    web_scope:
      "Only explicitly supplied URLs; no search engine, crawling, login or whole-web search.",
    source_upload: false,
    limitations: [
      "Exact bytes or text overlap do not determine ownership, copying direction, infringement, fair use or license compatibility.",
      "No visual/audio similarity, logo search, trademark database search, patent analysis, or inaccessible/paywalled/deleted-content coverage.",
      "Comparison samples at most 200 local files and 8000 tokens per text file, using 5-token hashes; common boilerplate can match and transformed copies can be missed.",
      "A clean comparison covers only the fetched references and sampled local files, never the web.",
      "Arbitrary hosts require direct public IPv4 pinned HTTPS. Only fixed public reference providers may use the trusted operator-configured proxy; its DNS/egress policy remains a trust boundary. Redirects, credentials and compressed bodies are refused.",
    ],
    disclaimer: DISCLAIMER,
  };
}
