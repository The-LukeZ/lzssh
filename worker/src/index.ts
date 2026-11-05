import { HEX_ID, tokenOk, verifyRequest } from "./auth";
import type { CallCtx, OpResult } from "./types";

export { Mailbox } from "./mailbox";

export const MAX_BODY = 1024 * 1024;

type Route =
  | { op: "post" | "list"; mailbox: string }
  | { op: "remove"; mailbox: string; id: string }
  | { op: "allow" | "disallow"; mailbox: string; peer: string }
  | { op: "pairing"; mailbox: string };

function route(method: string, path: string): Route | null {
  const p = path.split("/");
  // ["", "v1", "mailbox", mailbox, ...rest]
  if (p[1] !== "v1" || p[2] !== "mailbox" || !HEX_ID.test(p[3] ?? "")) return null;
  const mailbox = p[3];
  const rest = p.slice(4);
  if (rest.length === 0) {
    if (method === "POST") return { op: "post", mailbox };
    if (method === "GET") return { op: "list", mailbox };
  } else if (rest.length === 1 && rest[0] === "pairing") {
    if (method === "PUT") return { op: "pairing", mailbox };
  } else if (rest.length === 1 && method === "DELETE" && /^[A-Za-z0-9-]{1,64}$/.test(rest[0])) {
    return { op: "remove", mailbox, id: rest[0] };
  } else if (rest.length === 2 && rest[0] === "allow" && HEX_ID.test(rest[1])) {
    if (method === "PUT") return { op: "allow", mailbox, peer: rest[1] };
    if (method === "DELETE") return { op: "disallow", mailbox, peer: rest[1] };
  }
  return null;
}

const json = (status: number, body?: unknown) =>
  body === undefined ? new Response(null, { status }) : Response.json(body, { status });

async function dispatch(env: Env, r: Route, ctx: CallCtx, body: Uint8Array, ticket: string | null): Promise<OpResult> {
  const stub = env.MAILBOX.getByName(r.mailbox);
  const text = new TextDecoder().decode(body);
  const parse = (): unknown => {
    try {
      return JSON.parse(text);
    } catch {
      return null;
    }
  };
  switch (r.op) {
    case "list":
      return stub.list(ctx);
    case "post":
      return stub.post(ctx, parse(), body.length, ticket);
    case "remove":
      return stub.remove(ctx, r.id);
    case "allow":
      return stub.allow(ctx, r.peer);
    case "disallow":
      return stub.disallow(ctx, r.peer);
    case "pairing": {
      const b = parse() as { ticket_hash?: unknown; expires?: unknown } | null;
      return stub.setPairing(ctx, b?.ticket_hash, b?.expires);
    }
  }
}

export default {
  async fetch(req, env): Promise<Response> {
    const r = route(req.method, new URL(req.url).pathname);
    if (!r) return json(404, { error: "not_found" });
    if (!(await tokenOk(req.headers.get("Authorization"), env.ACCESS_TOKEN))) return json(401, { error: "token" });
    const declared = Number(req.headers.get("Content-Length") ?? "0");
    if (declared > MAX_BODY) return json(413, { error: "too_large" });
    const body = new Uint8Array(await req.arrayBuffer());
    if (body.length > MAX_BODY) return json(413, { error: "too_large" });
    const v = await verifyRequest(req, body, Math.floor(Date.now() / 1000));
    if ("error" in v) return json(401, v);
    const ctx: CallCtx = { mailbox: r.mailbox, caller: v.device, sig: v.sig };
    const res = await dispatch(env, r, ctx, body, req.headers.get("X-Lz-Pair-Ticket"));
    return json(res.status, res.body);
  },
} satisfies ExportedHandler<Env>;
