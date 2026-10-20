import { constants } from "node:fs";
import { open, opendir, realpath } from "node:fs/promises";
import path from "node:path";
import { createHash } from "node:crypto";
import { setImmediate } from "node:timers/promises";
import { authorizeRoot, contained, safePath } from "./scanner.js";
export interface IPFile {
  path: string;
  hash: string;
  bytes: number;
  text?: string;
}
export interface IPSnapshot {
  files: IPFile[];
  state: "complete" | "partial" | "cancelled";
  omissions: Record<string, number>;
  bytes: number;
}
const excluded = new Set([
  ".git",
  "node_modules",
  ".next",
  "dist",
  "build",
  "coverage",
  ".venv",
  "vendor",
]);
const assets =
  /\.(?:png|jpe?g|gif|webp|svg|ico|avif|mp3|wav|ogg|mp4|webm|woff2?|ttf|otf|fbx|obj|glb|gltf|blend)$/i;
export const isAsset = (name: string) => assets.test(name);
const supported =
  /(?:\.(?:[cm]?[jt]sx?|css|html?|md|txt|json|yaml|yml|lock|svg)$)|(?:^|\/)(?:LICENSE|LICENCE|COPYING|NOTICE|AUTHORS)(?:\.[a-z]+)?$/i;
export async function ipSnapshot(
  root: string,
  allowed: string[],
  signal?: AbortSignal,
): Promise<IPSnapshot> {
  const canonical = await authorizeRoot(root, allowed);
  const result: IPSnapshot = {
    files: [],
    state: "complete",
    omissions: {},
    bytes: 0,
  };
  const start = Date.now();
  let entries = 0,
    stop = false;
  const omit = (reason: string, partial = true) => {
    result.omissions[reason] = (result.omissions[reason] ?? 0) + 1;
    if (partial && result.state !== "cancelled") result.state = "partial";
  };
  const alive = () => {
    if (signal?.aborted) {
      result.state = "cancelled";
      stop = true;
    }
    if (Date.now() - start > 30000) {
      omit("time_limit");
      stop = true;
    }
    return !stop;
  };
  async function walk(dir: string, depth: number): Promise<void> {
    if (!alive()) return;
    if (depth > 30) {
      omit("depth_limit");
      return;
    }
    try {
      if (!contained(canonical, await realpath(dir))) {
        omit("directory_escape");
        return;
      }
      const d = await opendir(dir);
      for await (const e of d) {
        await setImmediate();
        if (!alive()) break;
        if (++entries > 10000) {
          omit("entry_limit");
          stop = true;
          break;
        }
        if (excluded.has(e.name)) {
          omit("excluded_directory", false);
          continue;
        }
        if (!/^[a-zA-Z0-9_.@+ \[\]()-]{1,160}$/.test(e.name)) {
          omit("unsafe_filename");
          continue;
        }
        const full = path.join(dir, e.name),
          relative = path.relative(canonical, full).split(path.sep).join("/");
        if (e.isSymbolicLink()) {
          omit("symlink");
          continue;
        }
        if (e.isDirectory()) {
          await walk(full, depth + 1);
          continue;
        }
        if (!e.isFile()) {
          omit("non_regular");
          continue;
        }
        if (!supported.test(relative) && !isAsset(relative)) {
          omit("unsupported_extension", false);
          continue;
        }
        if (result.files.length >= 1000) {
          omit("file_limit");
          stop = true;
          break;
        }
        let handle;
        try {
          handle = await open(
            full,
            constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
          );
          if (
            !contained(canonical, await realpath(`/proc/self/fd/${handle.fd}`))
          ) {
            omit("file_escape");
            continue;
          }
          const st = await handle.stat();
          if (!st.isFile()) {
            omit("non_regular");
            continue;
          }
          if (st.size > 1000000) {
            omit("oversized_file");
            continue;
          }
          const remaining = 20000000 - result.bytes;
          if (st.size > remaining) {
            omit("byte_limit");
            stop = true;
            break;
          }
          const buffer = Buffer.alloc(Math.min(1000000, remaining) + 1);
          let n = 0;
          while (n < buffer.length) {
            const chunk = await handle.read(buffer, n, buffer.length - n, null);
            if (!chunk.bytesRead) break;
            n += chunk.bytesRead;
          }
          if (n > 1000000 || n > remaining) {
            omit("file_grew");
            continue;
          }
          const content = buffer.subarray(0, n);
          result.bytes += n;
          const file: IPFile = {
            path: safePath(relative),
            hash: createHash("sha256").update(content).digest("hex"),
            bytes: n,
          };
          if (supported.test(relative) && !content.includes(0))
            file.text = content.toString("utf8");
          result.files.push(file);
        } catch {
          omit("unreadable_file");
        } finally {
          await handle?.close();
        }
      }
    } catch {
      omit("unreadable_directory");
    }
  }
  await walk(canonical, 0);
  alive();
  result.files.sort((a, b) => a.path.localeCompare(b.path));
  if (!result.files.length) omit("no_supported_files");
  return result;
}
