import { DurableObject } from "cloudflare:workers";
import { fromHex, HEX_ID, sha256Hex } from "./auth";
import type { CallCtx, Envelope, OpResult } from "./types";

const MAX_MESSAGES = 50;
const MAX_BYTES = 20 * 1024 * 1024;
const MESSAGE_TTL_SEC = 30 * 86400;
const REPLAY_WINDOW_SEC = 600;
const MAX_TICKET_SEC = 600;
const ALARM_EVERY_MS = 86400 * 1000;
const KINDS = new Set(["pair_request", "pair_accept", "payload"]);

const nowSec = () => Math.floor(Date.now() / 1000);
const FORBIDDEN: OpResult = { status: 403, body: { error: "forbidden" } };
const BAD: OpResult = { status: 400, body: { error: "bad_request" } };

function asEnvelope(x: unknown): Envelope | null {
  if (!x || typeof x !== "object") return null;
  const e = x as Record<string, unknown>;
  const str = (k: string, max: number) => typeof e[k] === "string" && (e[k] as string).length > 0 && (e[k] as string).length <= max;
  if (e.v !== 1 || !str("id", 64) || !str("from", 64) || !str("to", 64) || !KINDS.has(e.kind as string)) return null;
  if (!str("salt", 64) || !str("nonce", 64) || typeof e.ct !== "string") return null;
  return { v: 1, id: e.id, from: e.from, to: e.to, kind: e.kind, salt: e.salt, nonce: e.nonce, ct: e.ct } as Envelope;
}

/** One mailbox per device public key. Every method gets the verified caller from the Worker. */
export class Mailbox extends DurableObject<Env> {
  private sql: SqlStorage;

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    this.sql = ctx.storage.sql;
    ctx.blockConcurrencyWhile(async () => {
      this.sql.exec(`
        CREATE TABLE IF NOT EXISTS messages (id TEXT PRIMARY KEY, at INTEGER NOT NULL, size INTEGER NOT NULL, body TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS allow (peer TEXT PRIMARY KEY);
        CREATE TABLE IF NOT EXISTS pairing (k INTEGER PRIMARY KEY CHECK (k = 1), hash TEXT NOT NULL, expires INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS seen (sig TEXT PRIMARY KEY, at INTEGER NOT NULL);
      `);
    });
  }

  /** Replay protection: each signature is accepted once within the window. */
  private fresh(ctx: CallCtx): boolean {
    const now = nowSec();
    this.sql.exec("DELETE FROM seen WHERE at < ?", now - REPLAY_WINDOW_SEC);
    if (this.sql.exec("SELECT 1 FROM seen WHERE sig = ?", ctx.sig).toArray().length > 0) return false;
    this.sql.exec("INSERT INTO seen (sig, at) VALUES (?, ?)", ctx.sig, now);
    return true;
  }

  /** Replay check, then owner check. */
  private ownerOp(ctx: CallCtx): OpResult | null {
    if (!this.fresh(ctx)) return { status: 409, body: { error: "replay" } };
    if (ctx.caller !== ctx.mailbox) return FORBIDDEN;
    return null;
  }

  private async takeTicket(ticket: string | null): Promise<boolean> {
    const raw = ticket ? fromHex(ticket.toLowerCase()) : null;
    if (!raw || raw.length !== 32) return false;
    const row = this.sql.exec<{ hash: string; expires: number }>("SELECT hash, expires FROM pairing WHERE k = 1").toArray()[0];
    if (!row || row.expires < nowSec() || row.hash !== sha256Hex(raw)) return false;
    this.sql.exec("DELETE FROM pairing");
    return true;
  }

  async post(ctx: CallCtx, body: unknown, size: number, ticket: string | null): Promise<OpResult> {
    if (!this.fresh(ctx)) return { status: 409, body: { error: "replay" } };
    const env = asEnvelope(body);
    if (!env || env.from !== ctx.caller || env.to !== ctx.mailbox) return BAD;
    const allowed =
      ctx.caller === ctx.mailbox ||
      this.sql.exec("SELECT 1 FROM allow WHERE peer = ?", ctx.caller).toArray().length > 0 ||
      (env.kind === "pair_request" && (await this.takeTicket(ticket)));
    if (!allowed) return FORBIDDEN;
    if (this.sql.exec("SELECT 1 FROM messages WHERE id = ?", env.id).toArray().length > 0) return { status: 201 };
    const { n, bytes } = this.sql.exec<{ n: number; bytes: number }>("SELECT COUNT(*) AS n, COALESCE(SUM(size), 0) AS bytes FROM messages").one();
    if (n >= MAX_MESSAGES || bytes + size > MAX_BYTES) return { status: 507, body: { error: "full" } };
    this.sql.exec("INSERT INTO messages (id, at, size, body) VALUES (?, ?, ?, ?)", env.id, nowSec(), size, JSON.stringify(env));
    if ((await this.ctx.storage.getAlarm()) === null) await this.ctx.storage.setAlarm(Date.now() + ALARM_EVERY_MS);
    return { status: 201 };
  }

  async list(ctx: CallCtx): Promise<OpResult> {
    const deny = this.ownerOp(ctx);
    if (deny) return deny;
    const rows = this.sql.exec<{ body: string }>("SELECT body FROM messages ORDER BY at, rowid").toArray();
    return { status: 200, body: { messages: rows.map((r) => JSON.parse(r.body)) } };
  }

  async remove(ctx: CallCtx, id: string): Promise<OpResult> {
    const deny = this.ownerOp(ctx);
    if (deny) return deny;
    this.sql.exec("DELETE FROM messages WHERE id = ?", id);
    return { status: 204 };
  }

  async allow(ctx: CallCtx, peer: string): Promise<OpResult> {
    const deny = this.ownerOp(ctx);
    if (deny) return deny;
    if (!HEX_ID.test(peer)) return BAD;
    this.sql.exec("INSERT OR IGNORE INTO allow (peer) VALUES (?)", peer);
    return { status: 204 };
  }

  async disallow(ctx: CallCtx, peer: string): Promise<OpResult> {
    const deny = this.ownerOp(ctx);
    if (deny) return deny;
    this.sql.exec("DELETE FROM allow WHERE peer = ?", peer);
    return { status: 204 };
  }

  async setPairing(ctx: CallCtx, hash: unknown, expires: unknown): Promise<OpResult> {
    const deny = this.ownerOp(ctx);
    if (deny) return deny;
    const now = nowSec();
    if (typeof hash !== "string" || !HEX_ID.test(hash) || typeof expires !== "number" || !Number.isInteger(expires)) return BAD;
    if (expires <= now || expires > now + MAX_TICKET_SEC) return BAD;
    this.sql.exec("INSERT OR REPLACE INTO pairing (k, hash, expires) VALUES (1, ?, ?)", hash, expires);
    return { status: 204 };
  }

  async alarm(): Promise<void> {
    this.sql.exec("DELETE FROM messages WHERE at < ?", nowSec() - MESSAGE_TTL_SEC);
    this.sql.exec("DELETE FROM seen WHERE at < ?", nowSec() - REPLAY_WINDOW_SEC);
    const { n } = this.sql.exec<{ n: number }>("SELECT COUNT(*) AS n FROM messages").one();
    if (n > 0) await this.ctx.storage.setAlarm(Date.now() + ALARM_EVERY_MS);
  }
}
