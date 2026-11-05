import { DurableObject } from "cloudflare:workers";
import type { CallCtx, OpResult } from "./types";

const TODO: OpResult = { status: 501 };

export class Mailbox extends DurableObject<Env> {
  async list(_ctx: CallCtx): Promise<OpResult> {
    return { status: 200, body: { messages: [] } };
  }
  async post(_ctx: CallCtx, _env: unknown, _size: number, _ticket: string | null): Promise<OpResult> {
    return TODO;
  }
  async remove(_ctx: CallCtx, _id: string): Promise<OpResult> {
    return TODO;
  }
  async allow(_ctx: CallCtx, _peer: string): Promise<OpResult> {
    return TODO;
  }
  async disallow(_ctx: CallCtx, _peer: string): Promise<OpResult> {
    return TODO;
  }
  async setPairing(_ctx: CallCtx, _hash: unknown, _expires: unknown): Promise<OpResult> {
    return TODO;
  }
}
