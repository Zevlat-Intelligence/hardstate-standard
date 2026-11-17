// helpers.ts — test keys: Ed25519 institutional keys and a software "passkey" (P-256) that produces real WebAuthn
// assertions, so the tests exercise the same verification path a browser's authenticator does.

import {
  addOp, anchorScript, b64, b64url, concat, ed25519KeyId, eventHash, eventHashHex, hex, inclusionPath, leafOf, newTimestamp,
  reverse, rootOf, serializeDetached, sha256, signEd25519, utf8,
  type Bytes, type HardStateProof, type HssEvent, type KeyInfo, type Signature, type SignedEvent, type Timestamp,
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

// ── A complete proof for the demo log's inspection, checked against a fake pair of Bitcoin explorers ──────────────────

export async function confirmedTimestamp(root: Bytes, height = 900_000): Promise<{ ts: Timestamp; attested: Bytes }> {
  const ts = newTimestamp(root);
  const a = await addOp(ts, { tag: 0xf0, arg: hex.decode("00112233445566778899aabbccddeeff") });
  const b = await addOp(a, { tag: 0x08 });
  b.attestations.push({ kind: "pending", uri: "https://alice.btc.calendar.opentimestamps.org" });
  const c = await addOp(b, { tag: 0xf1, arg: hex.decode("aa".repeat(32)) });
  const d = await addOp(c, { tag: 0x08 });
  const e = await addOp(d, { tag: 0x08 });
  e.attestations.push({ kind: "bitcoin", height });
  return { ts, attested: e.msg };
}

export async function buildProof() {
  const demo = await demoLog();
  const subject = demo.log[3];
  const hash = await eventHashHex(subject.event);
  const others = await Promise.all([1, 2, 3, 4].map((i) => leafOf("stamp", new Uint8Array(32).fill(i))));
  const leaves = [...others.slice(0, 2), await leafOf("event", hex.decode(hash)), ...others.slice(2)];
  const root = await rootOf(leaves);
  const { ts, attested } = await confirmedTimestamp(root);
  const dayLeaves = [await leafOf("batch", new Uint8Array(32).fill(9)), await leafOf("batch", root)];
  const dayRoot = await rootOf(dayLeaves);
  const txid = "ab".repeat(32);
  const blocks = { 900000: { id: "00".repeat(31) + "01", merkle_root: hex.encode(reverse(attested)), timestamp: 1_792_000_000 } };
  const fakeFetch = (async (url: string) => {
    const u = String(url);
    let m = u.match(/block-height\/(\d+)$/);
    if (m) return new Response(blocks[+m[1] as 900000]?.id ?? "", { status: blocks[+m[1] as 900000] ? 200 : 404 });
    m = u.match(/block\/([0-9a-f]{64})$/);
    if (m) return Response.json({ id: m[1], height: 900000, merkle_root: blocks[900000].merkle_root, timestamp: blocks[900000].timestamp });
    m = u.match(/tx\/([0-9a-f]{64})$/);
    if (m) return Response.json({ txid: m[1], vout: [{ scriptpubkey: hex.encode(anchorScript(dayRoot)), scriptpubkey_type: "op_return" }], status: { confirmed: true, block_height: 900010, block_hash: "cc".repeat(32), block_time: 1_792_006_000 } });
    return new Response("not found", { status: 404 });
  }) as typeof fetch;
  const proof: HardStateProof = {
    hardstate: "proof", hss: 1,
    subject: { kind: "event", signed: subject, hash },
    authority: [demo.log[0], demo.log[1]],
    batch: { id: "b-1", closedAt: "2026-10-20T10:10:00Z", root: hex.encode(root), size: leaves.length, index: 2, path: (await inclusionPath(leaves, 2)).map(hex.encode) },
    ots: b64.encode(serializeDetached(ts)),
    anchor: { network: "bitcoin", txid, root: hex.encode(dayRoot), size: 2, index: 1, path: (await inclusionPath(dayLeaves, 1)).map(hex.encode) },
    issuedAt: new Date().toISOString(),
  };
  return { proof, fakeFetch, demo };
}
