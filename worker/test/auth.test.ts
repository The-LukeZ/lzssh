import { describe, expect, it } from "vitest";
import { signingString } from "../src/auth";
import { BASE, call, newDevice, now, signedRequest } from "./helpers";

const own = async () => {
  const d = await newDevice();
  return { d, path: `/v1/mailbox/${d.hex}` };
};

describe("request authentication", () => {
  it("signing string is exact", async () => {
    expect(signingString("POST", "/v1/mailbox/ab", "1700000000", "00112233445566778899aabbccddeeff", new TextEncoder().encode("{}"))).toBe(
      "lzssh-req-v1\nPOST\n/v1/mailbox/ab\n1700000000\n00112233445566778899aabbccddeeff\n44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
    );
  });

  it("missing token gives 401", async () => {
    const { d, path } = await own();
    expect((await call(await signedRequest(d, "GET", path, "", { token: null }))).status).toBe(401);
  });

  it("wrong token gives 401", async () => {
    const { d, path } = await own();
    expect((await call(await signedRequest(d, "GET", path, "", { token: "nope" }))).status).toBe(401);
  });

  it("bad signature gives 401", async () => {
    const { d, path } = await own();
    const other = await newDevice();
    expect((await call(await signedRequest(d, "GET", path, "", { signer: other }))).status).toBe(401);
  });

  it("clock_skew_is_reported_as_clock", async () => {
    const { d, path } = await own();
    const r = await call(await signedRequest(d, "GET", path, "", { time: now() - 301 }));
    expect(r.status).toBe(401);
    expect(await r.json()).toEqual({ error: "clock" });
  });

  it("good request reaches the mailbox", async () => {
    const { d, path } = await own();
    const r = await call(await signedRequest(d, "GET", path));
    expect(r.status).toBe(200);
    expect(await r.json()).toEqual({ messages: [] });
  });

  it("unknown route gives 404", async () => {
    const d = await newDevice();
    expect((await call(await signedRequest(d, "GET", "/v2/x"))).status).toBe(404);
    expect((await call(new Request(BASE + "/"))).status).toBe(404);
  });

  it("non-canonical signature encoding cannot bypass replay", async () => {
    const { d, path } = await own();
    const req = await signedRequest(d, "GET", path);
    const sig = req.headers.get("X-Lz-Sig")!;
    expect((await call(req)).status).toBe(200);
    const urlSafe = sig.replace(/\+/g, "-").replace(/\//g, "_");
    for (const variant of [sig.replace(/=+$/, ""), urlSafe, urlSafe.replace(/=+$/, "")]) {
      const headers = new Headers(req.headers);
      headers.set("X-Lz-Sig", variant);
      expect((await call(new Request(req.url, { headers }))).status).not.toBe(200);
    }
  });

  it("two identical requests in the same second both pass (nonce)", async () => {
    const { d, path } = await own();
    const t = now();
    expect((await call(await signedRequest(d, "GET", path, "", { time: t }))).status).toBe(200);
    expect((await call(await signedRequest(d, "GET", path, "", { time: t }))).status).toBe(200);
  });

  it("missing or malformed nonce gives 401", async () => {
    const { d, path } = await own();
    expect((await call(await signedRequest(d, "GET", path, "", { nonce: "" }))).status).toBe(401);
    expect((await call(await signedRequest(d, "GET", path, "", { nonce: "XYZ" }))).status).toBe(401);
  });

  it("query string is rejected", async () => {
    const { d, path } = await own();
    const req = await signedRequest(d, "GET", path);
    expect((await call(new Request(req.url + "?x=1", { headers: req.headers }))).status).toBe(404);
  });

  it("streamed body over 1 MiB without Content-Length gives 413", async () => {
    const { d, path } = await own();
    const req = await signedRequest(d, "GET", path);
    const chunk = new Uint8Array(64 * 1024);
    let sent = 0;
    const body = new ReadableStream({
      pull(c) {
        if (sent > 1024 * 1024 + chunk.length) return c.close();
        sent += chunk.length;
        c.enqueue(chunk);
      },
    });
    const headers = new Headers(req.headers);
    headers.delete("Content-Length");
    const r = await call(new Request(BASE + path, { method: "POST", headers, body, duplex: "half" } as RequestInit));
    expect(r.status).toBe(413);
  });

  it("malformed device id gives 401", async () => {
    const { d, path } = await own();
    expect((await call(await signedRequest(d, "GET", path, "", { device: "ABC" }))).status).toBe(401);
  });
});

describe("entry module", () => {
  it("exports only the handler and the Durable Object (workerd rejects other exports)", async () => {
    const mod = await import("../src/index");
    expect(Object.keys(mod).sort()).toEqual(["Mailbox", "default"]);
  });
});
