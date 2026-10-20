import { scan, authorizeRoot } from "./scanner.js";
import { SafeError, type Scan } from "./models.js";
import { compare } from "./reports.js";
export class Service {
  private scans = new Map<string, { scan: Scan; expires: number }>();
  private busy = false;
  constructor(
    readonly roots: string[],
    private ttl = 30 * 60 * 1000,
  ) {}
  private expire() {
    for (const [id, item] of this.scans)
      if (item.expires < Date.now()) this.scans.delete(id);
  }
  async exclusive<T>(work: () => Promise<T>): Promise<T> {
    if (this.busy)
      throw new SafeError(
        "BUSY",
        "One scan or IP review per server session may run at a time.",
      );
    this.busy = true;
    try {
      return await work();
    } finally {
      this.busy = false;
    }
  }
  async run(root: string, options: unknown = {}, signal?: AbortSignal) {
    return this.exclusive(async () => {
      const result = await scan(root, this.roots, options, signal);
      this.expire();
      while (this.scans.size >= 8)
        this.scans.delete(this.scans.keys().next().value!);
      this.scans.set(result.id, {
        scan: result,
        expires: Date.now() + this.ttl,
      });
      return result;
    });
  }
  get(id: string) {
    this.expire();
    const item = this.scans.get(id);
    if (!item)
      throw new SafeError(
        "NOT_FOUND",
        "Scan is unknown, expired or evicted. Re-scan the authorized root.",
      );
    return item.scan;
  }
  purge() {
    this.scans.clear();
    return { purged: true };
  }
  async verify(id: string, signal?: AbortSignal) {
    const base = this.get(id);
    const head = await this.run(
      base.root,
      { limits: base.limits, include_rules: base.executed_rules },
      signal,
    );
    return { ...compare(base, head), new_scan_id: head.id };
  }
  async health() {
    await Promise.all(this.roots.map((r) => authorizeRoot(r, this.roots)));
    return {
      ready: true,
      transport: "stdio",
      network_default: false,
      optional_network_tool: "juriscan_ip_web_compare",
      source_mutation: false,
      retention_minutes: this.ttl / 60000,
      max_retained_scans: 8,
    };
  }
}
