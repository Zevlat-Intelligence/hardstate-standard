// sig.ts — checking who signed an event. Officials sign with a passkey: the WebAuthn assertion's challenge is the event
// hash, so the authenticator's signature over authenticatorData ‖ sha256(clientDataJSON) binds the person's device to
// that exact event. Systems integrating server-to-server sign the 32-byte event hash with an Ed25519 key instead.
// WebCrypto only (the approach of rivrwa's webauthn.ts, extended to SPKI keys and the three COSE algorithms).

import { b64url, concat, equal, sha256, utf8, type Bytes } from "./bytes.ts";
import { eventHash, type HssEvent, type KeyInfo, type Signature } from "./event.ts";

/** DER `SEQUENCE { INTEGER r, INTEGER s }` → the 64-byte r ‖ s that WebCrypto verifies. */
export function derToRaw(der: Bytes): Bytes {
  if (der[0] !== 0x30) throw new Error("signature is not DER");
  let i = der[1] & 0x80 ? 2 + (der[1] & 0x7f) : 2;
  const int = () => {
    if (der[i] !== 0x02) throw new Error("signature is not DER");
    const len = der[i + 1];
    let v = der.slice(i + 2, i + 2 + len);
    i += 2 + len;
    while (v.length > 32 && v[0] === 0) v = v.slice(1);
    return concat(new Uint8Array(32 - v.length), v);
  };
  return concat(int(), int());
}

// Typed off crypto.subtle itself so the same file checks against DOM and Workers type libraries.
type ImportAlg = Parameters<typeof crypto.subtle.importKey>[2];
type VerifyAlg = Parameters<typeof crypto.subtle.verify>[0];

const ALGS: Record<number, { imp: ImportAlg; ver: VerifyAlg; der?: boolean }> = {
  [-7]: { imp: { name: "ECDSA", namedCurve: "P-256" }, ver: { name: "ECDSA", hash: "SHA-256" }, der: true },
  [-257]: { imp: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, ver: { name: "RSASSA-PKCS1-v1_5" } },
  [-8]: { imp: { name: "Ed25519" }, ver: { name: "Ed25519" } },
};

async function verifyRaw(alg: number, spki: Bytes, sig: Bytes, data: Bytes): Promise<boolean> {
  const a = ALGS[alg];
  if (!a) throw new Error(`unsupported key algorithm ${alg}`);
  const key = await crypto.subtle.importKey("spki", spki, a.imp, false, ["verify"]);
  return crypto.subtle.verify(a.ver, key, a.der ? derToRaw(sig) : sig, data);
}

/** Is `origin` a page allowed to use passkeys for `rpId` (the host itself or a subdomain, over https or localhost)? */
export function originMatches(origin: string, rpId: string): boolean {
  try {
    const u = new URL(origin);
    const hostOk = u.hostname === rpId || u.hostname.endsWith(`.${rpId}`);
    const secure = u.protocol === "https:" || u.hostname === "localhost" || u.hostname === "127.0.0.1";
    return hostOk && secure;
  } catch { return false; }
}

/**
 * Checks `sig` over `event` against `key`. Throws with the reason when anything is off; returns the details a verifier
 * shows (the origin a passkey signed on).
 */
export async function verifyEventSignature(event: HssEvent, sig: Signature, key: KeyInfo): Promise<{ origin?: string }> {
  if (event.actor !== key.id) throw new Error("event actor is not this key");
  return verifyHashSignature(await eventHash(event), sig, key, "event");
}

/**
 * Checks `sig` over a 32-byte `hash` against `key`: Ed25519 over the hash itself, or a passkey assertion whose challenge
 * is the hash. `what` names the signed thing in error messages. Events use it through verifyEventSignature; operator
 * requests (operator.ts) sign a domain-separated hash, so neither can be replayed as the other.
 */
export async function verifyHashSignature(hash: Bytes, sig: Signature, key: KeyInfo, what = "request"): Promise<{ origin?: string }> {
  if (sig.kind !== key.kind) throw new Error(`a ${key.kind} key cannot produce a ${sig.kind} signature`);
  const spki = b64url.decode(key.publicKey);

  if (sig.kind === "ed25519") {
    if (!(await verifyRaw(-8, spki, b64url.decode(sig.signature), hash))) throw new Error("bad Ed25519 signature");
    return {};
  }

  const clientRaw = b64url.decode(sig.clientDataJSON);
  const client = JSON.parse(new TextDecoder().decode(clientRaw)) as { type?: string; challenge?: string; origin?: string; crossOrigin?: boolean };
  if (client.type !== "webauthn.get") throw new Error("not a WebAuthn assertion");
  if (client.challenge !== b64url.encode(hash)) throw new Error(`the passkey signed a different ${what} (challenge mismatch)`);
  if (!key.rpId || !client.origin || !originMatches(client.origin, key.rpId)) throw new Error(`origin ${client.origin} is not allowed for ${key.rpId}`);
  if (client.crossOrigin) throw new Error("cross-origin assertion");

  const auth = b64url.decode(sig.authenticatorData);
  if (auth.length < 37 || !equal(auth.slice(0, 32), await sha256(utf8(key.rpId)))) throw new Error("rpId mismatch");
  if (!(auth[32] & 0x01)) throw new Error("user presence flag not set");

  const signed = concat(auth, await sha256(clientRaw));
  if (!(await verifyRaw(key.alg, spki, b64url.decode(sig.signature), signed))) throw new Error("bad passkey signature");
  return { origin: client.origin };
}

/** Server-to-server signing: an Ed25519 signature over the 32-byte event hash. */
export async function signEd25519(event: HssEvent, privateKey: CryptoKey): Promise<Signature> {
  const sig = new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, privateKey, await eventHash(event)));
  return { kind: "ed25519", signature: b64url.encode(sig) };
}

/** Whether the authenticator also verified the user (PIN / biometrics), not only their presence. */
export const userVerified = (sig: Signature) => sig.kind === "passkey" && !!(b64url.decode(sig.authenticatorData)[32] & 0x04);
