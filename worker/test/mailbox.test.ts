import { env } from "cloudflare:workers";
import { runDurableObjectAlarm, runInDurableObject } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { call, newDevice, now, signedRequest, type Dev } from "./helpers";

const hex = (b: ArrayBuffer | Uint8Array) => [...new Uint8Array(b)].map((x) => x.toString(16).padStart(2, "0")).join("");
const mb = (d: Dev) => `/v1/mailbox/${d.hex}`;

function envelope(from: Dev, to: Dev, kind = "payload", ct = "Y3Q=", id = crypto.randomUUID()) {
  return JSON.stringify({ v: 1, id, from: from.hex, to: to.hex, kind, salt: "c2FsdA==", nonce: "bm9uY2U=", ct });
}

async function post(from: Dev, to: Dev, body = envelope(from, to), ticket?: string) {
  return call(await signedRequest(from, "POST", mb(to), body, { ticket }));
}
async function list(caller: Dev, owner: Dev = caller) {
  return call(await signedRequest(caller, "GET", mb(owner)));
}
async function allow(owner: Dev, peer: Dev, method = "PUT") {
  return call(await signedRequest(owner, method, `${mb(owner)}/allow/${peer.hex}`));
}
async function newTicket(owner: Dev, expires = now() + 600) {
  const ticket = crypto.getRandomValues(new Uint8Array(32));
  const ticket_hash = hex(await crypto.subtle.digest("SHA-256", ticket));
  const r = await call(await signedRequest(owner, "PUT", `${mb(owner)}/pairing`, JSON.stringify({ ticket_hash, expires })));
  return { ticket: hex(ticket), status: r.status };
}
const stubOf = (d: Dev) => env.MAILBOX.getByName(d.hex);

describe("mailbox", () => {
  it("owner reads own mailbox; foreign read gives 403", async () => {
    const [a, b] = [await newDevice(), await newDevice()];
    expect((await list(a)).status).toBe(200);
    expect((await list(b, a)).status).toBe(403);
  });

  it("foreign delete gives 403", async () => {
    const [a, b] = [await newDevice(), await newDevice()];
    expect((await call(await signedRequest(b, "DELETE", `${mb(a)}/some-id`))).status).toBe(403);
  });

  it("sender not on allow list gives 403; after A allows B, B's post gives 201 and A lists it", async () => {
    const [a, b] = [await newDevice(), await newDevice()];
    expect((await post(b, a)).status).toBe(403);
    expect((await allow(a, b)).status).toBe(204);
    const body = envelope(b, a);
    expect((await post(b, a, body)).status).toBe(201);
    const msgs = ((await (await list(a)).json()) as { messages: unknown[] }).messages;
    expect(msgs).toEqual([JSON.parse(body)]);
  });

  it("disallow stops B again (403)", async () => {
    const [a, b] = [await newDevice(), await newDevice()];
    await allow(a, b);
    expect((await allow(a, b, "DELETE")).status).toBe(204);
    expect((await post(b, a)).status).toBe(403);
  });

  it("from must equal caller (400)", async () => {
    const [a, b, c] = [await newDevice(), await newDevice(), await newDevice()];
    await allow(a, b);
    expect((await post(b, a, envelope(c, a))).status).toBe(400);
    expect((await post(b, a, "not json")).status).toBe(400);
    expect((await post(b, a, envelope(b, c))).status).toBe(400);
  });

  it("replay gives 409", async () => {
    const a = await newDevice();
    const t = now();
    expect((await call(await signedRequest(a, "GET", mb(a), "", { time: t }))).status).toBe(200);
    expect((await call(await signedRequest(a, "GET", mb(a), "", { time: t }))).status).toBe(409);
  });

  it("pair ticket accepted once, then 403", async () => {
    const [a, b] = [await newDevice(), await newDevice()];
    const { ticket, status } = await newTicket(a);
    expect(status).toBe(204);
    expect((await post(b, a, envelope(b, a, "pair_request"), ticket)).status).toBe(201);
    expect((await post(b, a, envelope(b, a, "pair_request"), ticket)).status).toBe(403);
  });

  it("expired ticket gives 403", async () => {
    const [a, b] = [await newDevice(), await newDevice()];
    const { ticket } = await newTicket(a);
    await runInDurableObject(stubOf(a), async (_i, state) => {
      state.storage.sql.exec("UPDATE pairing SET expires = ?", now() - 1);
    });
    expect((await post(b, a, envelope(b, a, "pair_request"), ticket)).status).toBe(403);
  });

  it("ticket only works for pair_request", async () => {
    const [a, b] = [await newDevice(), await newDevice()];
    const { ticket } = await newTicket(a);
    expect((await post(b, a, envelope(b, a, "payload"), ticket)).status).toBe(403);
  });

  it("pairing expiry beyond 600 s gives 400", async () => {
    const a = await newDevice();
    expect((await newTicket(a, now() + 601 + 5)).status).toBe(400);
    expect((await newTicket(a, now() - 1)).status).toBe(400);
  });

  it("body over 1 MiB gives 413", async () => {
    const a = await newDevice();
    expect((await post(a, a, envelope(a, a, "payload", "A".repeat(1024 * 1024)))).status).toBe(413);
  });

  it("51st message gives 507", async () => {
    const a = await newDevice();
    for (let i = 0; i < 50; i++) expect((await post(a, a)).status).toBe(201);
    expect((await post(a, a)).status).toBe(507);
  });

  it("message bytes over 20 MiB gives 507", async () => {
    const a = await newDevice();
    const big = () => envelope(a, a, "payload", "A".repeat(1_000_000));
    for (let i = 0; i < 20; i++) expect((await post(a, a, big())).status).toBe(201);
    expect((await post(a, a, big())).status).toBe(507);
  });

  it("duplicate id is accepted once", async () => {
    const a = await newDevice();
    const id = crypto.randomUUID();
    const body = envelope(a, a, "payload", "Y3Q=", id);
    expect((await post(a, a, body)).status).toBe(201);
    // Same body again (new time, so it is not a replay).
    expect((await call(await signedRequest(a, "POST", mb(a), body, { time: now() - 5 }))).status).toBe(201);
    expect(((await (await list(a)).json()) as { messages: unknown[] }).messages).toHaveLength(1);
  });

  it("alarm deletes messages older than 30 days", async () => {
    const a = await newDevice();
    await post(a, a);
    await post(a, a);
    await runInDurableObject(stubOf(a), async (_i, state) => {
      state.storage.sql.exec("UPDATE messages SET at = ? WHERE rowid = (SELECT MIN(rowid) FROM messages)", now() - 31 * 86400);
    });
    expect(await runDurableObjectAlarm(stubOf(a))).toBe(true);
    expect(((await (await list(a)).json()) as { messages: unknown[] }).messages).toHaveLength(1);
  });

  it("delete then list no longer shows it", async () => {
    const a = await newDevice();
    const id = crypto.randomUUID();
    await post(a, a, envelope(a, a, "payload", "Y3Q=", id));
    expect((await call(await signedRequest(a, "DELETE", `${mb(a)}/${id}`))).status).toBe(204);
    expect(((await (await list(a)).json()) as { messages: unknown[] }).messages).toHaveLength(0);
  });
});
