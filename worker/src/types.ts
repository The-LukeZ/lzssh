export type Kind = "pair_request" | "pair_accept" | "payload";

export type Envelope = {
  v: 1;
  id: string;
  from: string;
  to: string;
  kind: Kind;
  salt: string;
  nonce: string;
  ct: string;
};

export type OpResult = { status: number; body?: unknown };

/** Identity of a verified request, passed to every Mailbox call. */
export type CallCtx = { mailbox: string; caller: string; sig: string };
