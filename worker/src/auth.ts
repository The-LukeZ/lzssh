/** Request authentication: the shared access token, then the device's Ed25519 signature. */
import { Buffer } from "node:buffer";
import { createHash, createPublicKey, timingSafeEqual, verify } from "node:crypto";

export const HEX_ID = /^[0-9a-f]{64}$/;
/** Canonical standard base64 of a 64-byte signature (no whitespace, exact padding). */
const SIG_B64 = /^[A-Za-z0-9+/]{86}==$/;
const CLOCK_WINDOW_SEC = 300;

export function sha256Hex(b: Uint8Array | string): string {
  return createHash("sha256").update(b).digest("hex");
}

/** Lowercase hex to bytes, or null when malformed. */
export function fromHex(s: string): Buffer | null {
  return /^(?:[0-9a-f]{2})*$/.test(s) ? Buffer.from(s, "hex") : null;
}

/** `lzssh-req-v1\n METHOD \n PATH \n TIME \n hex(sha256(body))` */
export function signingString(method: string, path: string, time: string, body: Uint8Array): string {
  return `lzssh-req-v1\n${method}\n${path}\n${time}\n${sha256Hex(body)}`;
}

/** Constant-time check of `Authorization: Bearer <token>` (both sides hashed to a fixed size). */
export function tokenOk(header: string | null, secret: string): boolean {
  if (!header || !secret || !header.startsWith("Bearer ")) return false;
  const a = createHash("sha256").update(header.slice(7)).digest();
  const b = createHash("sha256").update(secret).digest();
  return timingSafeEqual(a, b);
}

export type Verified = { device: string; sig: string };
export type AuthFailure = { error: "auth" | "clock" };

/** On success `sig` is the hex of the signature bytes: a canonical key for replay checks. */
export function verifyRequest(req: Request, path: string, body: Uint8Array, nowSec: number): Verified | AuthFailure {
  const device = req.headers.get("X-Lz-Device") ?? "";
  const time = req.headers.get("X-Lz-Time") ?? "";
  const sigB64 = req.headers.get("X-Lz-Sig") ?? "";
  if (!HEX_ID.test(device) || !/^\d{1,12}$/.test(time) || !SIG_B64.test(sigB64)) return { error: "auth" };
  if (Math.abs(nowSec - Number(time)) > CLOCK_WINDOW_SEC) return { error: "clock" };
  const sig = Buffer.from(sigB64, "base64");
  try {
    const key = createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: Buffer.from(device, "hex").toString("base64url") }, format: "jwk" });
    if (!verify(null, Buffer.from(signingString(req.method, path, time, body)), key, sig)) return { error: "auth" };
  } catch {
    return { error: "auth" };
  }
  return { device, sig: sig.toString("hex") };
}
