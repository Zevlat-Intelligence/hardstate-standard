import { test } from "node:test";
import assert from "node:assert/strict";
import { b64url, concat, hex, publicKeyFromAttestation, type Bytes } from "../src/index.ts";

// Tiny CBOR encoder, just for building test attestation objects.
const len = (major: number, n: number): Bytes => (n < 24 ? Uint8Array.of((major << 5) | n) : n < 256 ? Uint8Array.of((major << 5) | 24, n) : Uint8Array.of((major << 5) | 25, n >> 8, n & 0xff));
type V = number | Bytes | string | Map<V, V>;
function enc(v: V): Bytes {
  if (typeof v === "number") return v >= 0 ? len(0, v) : len(1, -1 - v);
  if (typeof v === "string") { const b = new TextEncoder().encode(v); return concat(len(3, b.length), Uint8Array.from(b)); }
  if (v instanceof Uint8Array) return concat(len(2, v.length), v);
  return concat(len(5, v.size), ...[...v].flatMap(([k, x]) => [enc(k), enc(x)]));
}

async function attestation(cose: Map<V, V>) {
  const credId = crypto.getRandomValues(new Uint8Array(16));
  const authData = concat(new Uint8Array(32), Uint8Array.of(0x45), new Uint8Array(4), new Uint8Array(16), Uint8Array.of(0, credId.length), credId, enc(cose));
  return enc(new Map<V, V>([["fmt", "none"], ["attStmt", new Map()], ["authData", authData]]));
}

test("COSE: P-256 (ES256) key from an attestationObject matches the original SPKI", async () => {
  const kp = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])) as CryptoKeyPair;
  const jwk = await crypto.subtle.exportKey("jwk", kp.publicKey);
  const cose = new Map<V, V>([[1, 2], [3, -7], [-1, 1], [-2, b64url.decode(jwk.x!)], [-3, b64url.decode(jwk.y!)]]);
  const { spki, alg } = await publicKeyFromAttestation(await attestation(cose));
  assert.equal(alg, -7);
  assert.equal(hex.encode(spki), hex.encode(new Uint8Array(await crypto.subtle.exportKey("spki", kp.publicKey))));
});

test("COSE: Ed25519 (EdDSA) key from an attestationObject matches the original SPKI", async () => {
  const kp = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])) as CryptoKeyPair;
  const jwk = await crypto.subtle.exportKey("jwk", kp.publicKey);
  const cose = new Map<V, V>([[1, 1], [3, -8], [-1, 6], [-2, b64url.decode(jwk.x!)]]);
  const { spki, alg } = await publicKeyFromAttestation(await attestation(cose));
  assert.equal(alg, -8);
  assert.equal(hex.encode(spki), hex.encode(new Uint8Array(await crypto.subtle.exportKey("spki", kp.publicKey))));
});

test("COSE: unsupported algorithms and missing credential data are rejected", async () => {
  await assert.rejects(publicKeyFromAttestation(await attestation(new Map<V, V>([[1, 2], [3, -35]]))), /unsupported/);
  const noCred = enc(new Map<V, V>([["fmt", "none"], ["authData", new Uint8Array(37)]]));
  await assert.rejects(publicKeyFromAttestation(noCred), /no attested credential/);
});
