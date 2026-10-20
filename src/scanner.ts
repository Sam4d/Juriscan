import { constants } from "node:fs";
import { open, realpath, lstat, opendir } from "node:fs/promises";
import path from "node:path";
import { createHash } from "node:crypto";
import { setImmediate } from "node:timers/promises";
import { detect } from "./detectors.js";
import { RULES, RULE_MAP } from "./rules.js";
import {
  DISCLAIMER,
  VERSION,
  ScanOptionsSchema,
  SafeError,
  type Scan,
  type Finding,
} from "./models.js";
export function safePath(value: string) {
  return value.replace(
    /sk_live_[a-zA-Z0-9]{20,}|gh[pousr]_[a-zA-Z0-9]{30,}|AKIA[A-Z0-9]{16}|[a-zA-Z0-9._+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g,
    "[REDACTED]",
  );
}
export const sha = (value: string) =>
  createHash("sha256").update(value).digest("hex");
const ignored = new Set([
  ".git",
  "node_modules",
  ".next",
  "dist",
  "build",
  "coverage",
  ".venv",
  "vendor",
  ".cache",
  ".turbo",
]);
const accepted =
  /\.(?:[cm]?[jt]sx?|json|sql|rules|ya?ml|toml|ini|env|pem|key)$|(?:^|\/)\.env(?:\.|$)/i;
export function contained(root: string, target: string) {
  const r = path.relative(root, target);
  return (
    r === "" ||
    (!r.startsWith(".." + path.sep) && r !== ".." && !path.isAbsolute(r))
  );
}
export async function authorizeRoot(
  root: string,
  allowedRoots: string[],
): Promise<string> {
  if (process.platform !== "linux")
    throw new SafeError(
      "UNSUPPORTED_PLATFORM",
      "This alpha requires Linux for descriptor-based file boundary checks.",
    );
  if (!path.isAbsolute(root) || allowedRoots.length === 0)
    throw new SafeError(
      "ROOT_DENIED",
      "An explicit absolute authorized root is required.",
    );
  try {
    const canonical = await realpath(root);
    const allowed = await Promise.all(allowedRoots.map((r) => realpath(r)));
    if (
      !allowed.some((a) => contained(a, canonical)) ||
      !(await lstat(canonical)).isDirectory()
    )
      throw new Error();
    return canonical;
  } catch {
    throw new SafeError(
      "ROOT_DENIED",
      "Root is unavailable or outside the configured authorization boundary.",
    );
  }
}
export async function scan(
  root: string,
  allowedRoots: string[],
  input: unknown = {},
  signal?: AbortSignal,
): Promise<Scan> {
  const options = ScanOptionsSchema.parse(input),
    limits = options.limits;
  const canonical = await authorizeRoot(root, allowedRoots);
  const selected = options.include_rules ?? RULES.map((r) => r.id);
  if (selected.some((id) => !RULE_MAP.has(id)))
    throw new SafeError("INVALID_RULE", "Unknown detector ID.");
  const findings: Finding[] = [],
    omissions: Record<string, number> = {},
    warnings: string[] = [],
    hashes: string[] = [];
  let files = 0,
    bytes = 0,
    visited = 0,
    stop = false,
    state: Scan["state"] = "complete";
  const started = Date.now();
  const omit = (reason: string) => {
    omissions[reason] = (omissions[reason] ?? 0) + 1;
  };
  const incomplete = (reason: string) => {
    if (state !== "cancelled") state = "partial";
    if (!warnings.includes(reason)) warnings.push(reason);
  };
  const check = () => {
    if (signal?.aborted) {
      state = "cancelled";
      stop = true;
      return false;
    }
    if (Date.now() - started >= limits.max_duration_ms) {
      incomplete("time_limit");
      stop = true;
      return false;
    }
    return !stop;
  };
  async function walk(dir: string): Promise<void> {
    if (!check()) return;
    let entries;
    try {
      if (!contained(canonical, await realpath(dir))) {
        omit("directory_escape");
        incomplete("unsafe_path");
        return;
      }
      entries = [];
      const directory = await opendir(dir);
      for await (const entry of directory) {
        if (!check()) break;
        if (entries.length + visited >= 20000) {
          incomplete("entry_limit");
          stop = true;
          break;
        }
        entries.push(entry);
      }
    } catch {
      omit("unreadable_directory");
      incomplete("unreadable_path");
      return;
    }
    entries.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
    for (const e of entries) {
      await setImmediate();
      if (!check()) break;
      if (++visited > 20000) {
        incomplete("entry_limit");
        stop = true;
        break;
      }
      if (ignored.has(e.name)) {
        omit("excluded_directory");
        continue;
      }
      // Reject control/markup characters and extremely long names before they can reach a report.
      if (!/^[a-zA-Z0-9_.@+ \[\]()-]{1,160}$/.test(e.name)) {
        omit("unsafe_filename");
        incomplete("unsafe_filename");
        continue;
      }
      const full = path.join(dir, e.name),
        relative = path.relative(canonical, full).split(path.sep).join("/");
      if (e.isSymbolicLink()) {
        omit("symlink");
        incomplete("symlinks_omitted");
        continue;
      }
      if (e.isDirectory()) {
        if (relative.split("/").length > 40) {
          omit("depth_limit");
          incomplete("depth_limit");
        } else await walk(full);
        continue;
      }
      if (!e.isFile()) {
        omit("non_regular");
        continue;
      }
      if (!accepted.test(relative)) {
        omit("unsupported_extension");
        continue;
      }
      if (files >= limits.max_files) {
        incomplete("file_limit");
        stop = true;
        break;
      }
      let handle;
      try {
        handle = await open(
          full,
          constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
        );
        // Pin the opened inode, then inspect its actual target BEFORE reading (Linux).
        const actual = await realpath(`/proc/self/fd/${handle.fd}`);
        if (!contained(canonical, actual)) {
          omit("file_escape");
          incomplete("unsafe_path");
          continue;
        }
        const st = await handle.stat();
        if (!st.isFile()) {
          omit("non_regular");
          continue;
        }
        if (st.size > limits.max_file_bytes) {
          omit("oversized_file");
          incomplete("oversized_file");
          continue;
        }
        if (bytes + st.size > limits.max_total_bytes) {
          incomplete("byte_limit");
          stop = true;
          break;
        }
        const buffer = Buffer.alloc(
          Math.min(limits.max_file_bytes, limits.max_total_bytes - bytes) + 1,
        );
        let count = 0;
        while (count < buffer.length) {
          const read = await handle.read(
            buffer,
            count,
            buffer.length - count,
            null,
          );
          if (read.bytesRead === 0) break;
          count += read.bytesRead;
        }
        if (
          count > limits.max_file_bytes ||
          bytes + count > limits.max_total_bytes
        ) {
          omit("file_grew");
          incomplete("byte_limit");
          continue;
        }
        const content = buffer.subarray(0, count);
        bytes += count;
        files++;
        if (content.includes(0)) {
          omit("binary");
          incomplete("binary_source");
          continue;
        }
        const text = content.toString("utf8"),
          source_hash = sha(text);
        hashes.push(relative + "\0" + source_hash);
        const occurrences = new Map<string, number>();
        for (const hit of detect({ path: relative, text, hash: source_hash })) {
          if (!selected.includes(hit.rule_id)) continue;
          if (findings.length >= limits.max_findings) {
            incomplete("finding_limit");
            stop = true;
            break;
          }
          const r = RULE_MAP.get(hit.rule_id)!;
          const occurrence = (occurrences.get(r.id) ?? 0) + 1;
          occurrences.set(r.id, occurrence);
          const fingerprint = sha(
            [r.id, relative, String(occurrence)].join("\0"),
          );
          findings.push({
            schema_version: "1",
            id: "finding_" + fingerprint.slice(0, 24),
            fingerprint,
            rule_id: r.id,
            rule_version: "1",
            title: r.title,
            domain: r.domain,
            classification: r.classification,
            severity: r.severity,
            confidence: r.confidence,
            location: { path: safePath(relative), line: hit.line },
            evidence: {
              id: "evidence_" + fingerprint.slice(0, 24),
              observation: r.observation,
              method: r.method,
              source_hash,
            },
            legal_status: "not_assessed",
            legal_refs: [],
            missing_facts: r.missing_facts,
            remediation: r.remediation,
            acceptance_tests: r.acceptance_tests,
            limitations: r.limitations,
            verification: "not_run",
          });
        }
      } catch (error) {
        if (error instanceof SafeError && error.code === "PARSE_FAILED") {
          omit("parse_failed");
          incomplete("parse_failed");
        } else {
          omit("unreadable_file");
          incomplete("unreadable_path");
        }
      } finally {
        await handle?.close();
      }
    }
  }
  await walk(canonical);
  check();
  if (files === 0) {
    incomplete("no_supported_files");
  }
  const project_id = "project_" + sha(canonical).slice(0, 24),
    snapshot_hash = sha(hashes.join("\n"));
  const id =
    "scan_" +
    sha(
      JSON.stringify({
        project_id,
        snapshot_hash,
        selected,
        limits,
        state,
        omissions,
        findings,
      }),
    ).slice(0, 24);
  return {
    schema_version: "1",
    id,
    created_at: new Date().toISOString(),
    version: VERSION,
    project_id,
    root: canonical,
    snapshot_hash,
    state,
    files_scanned: files,
    bytes_scanned: bytes,
    executed_rules: selected,
    omissions,
    warnings,
    findings,
    limits,
    disclaimer: DISCLAIMER,
  };
}
