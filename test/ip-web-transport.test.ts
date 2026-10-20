import { it, expect, vi, beforeEach } from "vitest";
import { EventEmitter } from "node:events";
const mocks = vi.hoisted(() => ({ lookup: vi.fn(), request: vi.fn() }));
vi.mock("node:dns/promises", () => ({ lookup: mocks.lookup }));
vi.mock("node:https", () => ({
  default: {
    Agent: class {
      destroy() {}
    },
    request: mocks.request,
  },
}));
import { fetchPublicReference } from "../src/ip-web.js";
beforeEach(() => {
  mocks.lookup.mockReset();
  mocks.request.mockReset();
  mocks.lookup.mockResolvedValue([{ address: "8.8.8.8", family: 4 }]);
});
function respond(
  status: number,
  body: Buffer,
  headers: Record<string, string> = {},
) {
  mocks.request.mockImplementation((_url, options, callback) => {
    const request = new EventEmitter() as EventEmitter & {
      end: () => void;
      destroy: () => void;
    };
    request.destroy = () => {};
    request.end = () =>
      queueMicrotask(() => {
        const response = new EventEmitter() as EventEmitter & {
          statusCode: number;
          headers: Record<string, string>;
          destroy: () => void;
        };
        response.statusCode = status;
        response.headers = { "content-type": "text/plain", ...headers };
        response.destroy = () => {};
        callback(response);
        if (status === 200) {
          response.emit("data", body);
          response.emit("end");
        }
      });
    return request;
  });
}
it("pins a validated public address, preserves hostname TLS identity and sends only GET headers", async () => {
  respond(200, Buffer.from("public reference"));
  const r = await fetchPublicReference("https://example.com/source", [
    "example.com",
  ]);
  expect(r.text).toBe("public reference");
  expect(r.sha256).toHaveLength(64);
  const options = mocks.request.mock.calls[0]![1];
  expect(options.method).toBe("GET");
  expect(options.servername).toBe("example.com");
  expect(options.rejectUnauthorized).not.toBe(false);
  const result = vi.fn();
  options.lookup("example.com", {}, result);
  expect(result).toHaveBeenCalledWith(null, "8.8.8.8", 4);
  expect(options.headers.Authorization).toBeUndefined();
  expect(options.headers.Cookie).toBeUndefined();
});
it("rejects DNS rebinding to private targets before issuing HTTPS", async () => {
  mocks.lookup.mockResolvedValue([{ address: "10.0.0.1", family: 4 }]);
  await expect(
    fetchPublicReference("https://example.com/x", ["example.com"]),
  ).rejects.toMatchObject({ code: "REFERENCE_ADDRESS_DENIED" });
  expect(mocks.request).not.toHaveBeenCalled();
});
it.each([301, 302, 307, 401, 404, 500])(
  "does not follow status %s redirects or authentication",
  async (status) => {
    respond(status, Buffer.alloc(0), { location: "https://127.0.0.1/" });
    await expect(
      fetchPublicReference("https://example.com/x", ["example.com"]),
    ).rejects.toMatchObject({ code: "REFERENCE_UNAVAILABLE" });
    expect(mocks.request).toHaveBeenCalledTimes(1);
  },
);
it("rejects oversized content even without content-length", async () => {
  respond(200, Buffer.alloc(1000001));
  await expect(
    fetchPublicReference("https://example.com/x", ["example.com"]),
  ).rejects.toMatchObject({ code: "REFERENCE_TOO_LARGE" });
});
it("rejects compressed responses rather than risking decompression bombs", async () => {
  respond(200, Buffer.from("x"), { "content-encoding": "gzip" });
  await expect(
    fetchPublicReference("https://example.com/x", ["example.com"]),
  ).rejects.toMatchObject({ code: "REFERENCE_ENCODING_DENIED" });
});
it("cancellation after DNS prevents a request", async () => {
  const c = new AbortController();
  c.abort();
  await expect(
    fetchPublicReference("https://example.com/x", ["example.com"], c.signal),
  ).rejects.toMatchObject({ code: "CANCELLED" });
  expect(mocks.request).not.toHaveBeenCalled();
});
it("permits the trusted operator proxy only for curated public reference providers", async () => {
  vi.stubEnv("HTTPS_PROXY", "http://operator-proxy.invalid:8080");
  respond(200, Buffer.from("public licensed reference"));
  try {
    const r = await fetchPublicReference(
      "https://raw.githubusercontent.com/owner/repo/main/LICENSE",
      ["raw.githubusercontent.com"],
    );
    expect(r.network_route).toBe("operator_proxy_curated_host");
    expect(mocks.lookup).not.toHaveBeenCalled();
    const options = mocks.request.mock.calls[0]![1];
    expect(options.lookup).toBeUndefined();
    expect(options.headers.Authorization).toBeUndefined();
  } finally {
    vi.unstubAllEnvs();
  }
});
