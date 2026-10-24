// helpers.ts — test keys: Ed25519 institutional keys and a software "passkey" (P-256) that produces real WebAuthn
// assertions, so the tests exercise the same verification path a browser's authenticator does.

import {
  b64url, concat, ed25519KeyId, eventHash, eventHashHex, hex, sha256, signEd25519, utf8,
  type Bytes, type HssEvent, type KeyInfo, type Signature, type SignedEvent,
} from "../src/index.ts";

export interface TestKey { info: KeyInfo; sign(e: HssEvent): Promise<Signature>; signHash(h: Bytes): Promise<Signature> }

export async function ed25519Key(role: KeyInfo["role"], label: string): Promise<TestKey> {
  const kp = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])) as CryptoKeyPair;
  const spki = new Uint8Array((await crypto.subtle.exportKey("spki", kp.publicKey)) as ArrayBuffer);
  const info: KeyInfo = { id: await ed25519KeyId(spki), kind: "ed25519", alg: -8, publicKey: b64url.encode(spki), role, label };
  const signHash = async (h: Bytes): Promise<Signature> => ({ kind: "ed25519", signature: b64url.encode(new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, kp.privateKey, h))) });
  return { info, sign: (e) => signEd25519(e, kp.privateKey), signHash };
}

/** raw r ‖ s (WebCrypto) → DER, as authenticators return ECDSA signatures. */
function rawToDer(raw: Bytes): Bytes {
  const int = (b: Bytes) => {
    let i = 0;
    while (i < b.length - 1 && b[i] === 0) i++;
    let v = b.slice(i);
    if (v[0] & 0x80) v = concat(new Uint8Array([0]), v);
    return concat(new Uint8Array([0x02, v.length]), v);
  };
  const body = concat(int(raw.slice(0, 32)), int(raw.slice(32)));
  return concat(new Uint8Array([0x30, body.length]), body);
}

export async function passkey(role: KeyInfo["role"], label: string, rpId = "app.hardstate.net", origin = `https://${rpId}`): Promise<TestKey> {
  const kp = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])) as CryptoKeyPair;
  const spki = new Uint8Array((await crypto.subtle.exportKey("spki", kp.publicKey)) as ArrayBuffer);
  const id = b64url.encode(crypto.getRandomValues(new Uint8Array(16)));
  const info: KeyInfo = { id, kind: "passkey", alg: -7, publicKey: b64url.encode(spki), role, label, rpId };
  const signHash = async (h: Bytes): Promise<Signature> => {
    const clientDataJSON = utf8(JSON.stringify({ type: "webauthn.get", challenge: b64url.encode(h), origin, crossOrigin: false }));
    const authenticatorData = concat(await sha256(utf8(rpId)), new Uint8Array([0x05, 0, 0, 0, 1]));
    const raw = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, kp.privateKey, concat(authenticatorData, await sha256(clientDataJSON))));
    return { kind: "passkey", authenticatorData: b64url.encode(authenticatorData), clientDataJSON: b64url.encode(clientDataJSON), signature: b64url.encode(rawToDer(raw)) };
  };
  return { info, sign: async (e) => signHash(await eventHash(e)), signHash };
}

/** A small log: issuer.create by an admin passkey, an official added, then the case events signed by the official. */
export async function demoLog(issuer = "demo-city") {
  const admin = await passkey("admin", "María Ruiz — Registrar");
  const official = await passkey("official", "Ana López — Building inspector");
  const log: SignedEvent[] = [];
  const append = async (signer: TestKey, partial: Omit<HssEvent, "hss" | "issuer" | "seq" | "prev" | "actor" | "ts">) => {
    const prev = log.length ? await eventHashHex(log[log.length - 1].event) : null;
    const event: HssEvent = { hss: 1, issuer, seq: log.length, prev, ts: new Date(Date.UTC(2026, 9, 20, 10, log.length)).toISOString(), actor: signer.info.id, ...partial };
    log.push({ event, sig: await signer.sign(event) });
    return log[log.length - 1];
  };
  await append(admin, { type: "issuer.create", public: { name: "Demo City", key: admin.info as never }, docs: [] });
  await append(admin, { type: "key.add", public: { key: official.info as never }, docs: [] });
  await append(official, { type: "case.open", case: "BP-2026-0042", public: { title: "Building permit" }, docs: [] });
  await append(official, { type: "case.inspect", case: "BP-2026-0042", public: { result: "pass" }, docs: [{ label: "Inspection report", commitment: hex.encode(new Uint8Array(32).fill(7)) }] });
  return { admin, official, log, append };
}
