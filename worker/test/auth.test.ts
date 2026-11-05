import { describe, expect, it } from "vitest";
import { signingString } from "../src/auth";
import { BASE, call, newDevice, now, signedRequest } from "./helpers";

const own = async () => {
  const d = await newDevice();
  return { d, path: `/v1/mailbox/${d.hex}` };
};

describe("request authentication", () => {
  it("signing string is exact", async () => {
    expect(await signingString("POST", "/v1/mailbox/ab", "1700000000", new TextEncoder().encode("{}"))).toBe(
      "lzssh-req-v1\nPOST\n/v1/mailbox/ab\n1700000000\n44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
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

  it("malformed device id gives 401", async () => {
    const { d, path } = await own();
    expect((await call(await signedRequest(d, "GET", path, "", { device: "ABC" }))).status).toBe(401);
  });
});
