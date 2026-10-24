// cose.ts — reading a passkey's public key from the registration response itself. Browsers expose it directly through
// AuthenticatorAttestationResponse.getPublicKey(), but some authenticators and password managers' WebAuthn layers do
// not implement that method; every one of them returns the attestationObject, whose authenticator data carries the
// credential public key as a COSE key. We decode just enough CBOR to get it, then let WebCrypto turn it into SPKI.

import { b64url, type Bytes } from "./bytes.ts";

type Cbor = number | Bytes | string | Cbor[] | Map<Cbor, Cbor> | boolean | null;

/** Minimal CBOR decoder (RFC 8949): unsigned/negative ints, byte and text strings, arrays, maps, simple values. */
function decodeCbor(b: Bytes, start = 0): { value: Cbor; end: number } {
  let i = start;
  const head = () => {
    const ib = b[i++], major = ib >> 5, info = ib & 0x1f;
    let n: number;
    if (info < 24) n = info;
    else if (info === 24) n = b[i++];
    else if (info === 25) { n = (b[i] << 8) | b[i + 1]; i += 2; }
    else if (info === 26) { n = ((b[i] << 24) >>> 0) + ((b[i + 1] << 16) | (b[i + 2] << 8) | b[i + 3]); i += 4; }
    else throw new Error("CBOR: unsupported length encoding");
    return { major, n, info };
  };
  const item = (): Cbor => {
    if (i >= b.length) throw new Error("CBOR: truncated");
    const { major, n, info } = head();
    switch (major) {
      case 0: return n;
      case 1: return -1 - n;
      case 2: { const v = b.slice(i, i + n); i += n; return v; }
      case 3: { const v = new TextDecoder().decode(b.slice(i, i + n)); i += n; return v; }
      case 4: { const a: Cbor[] = []; for (let k = 0; k < n; k++) a.push(item()); return a; }
      case 5: { const m = new Map<Cbor, Cbor>(); for (let k = 0; k < n; k++) { const key = item(); m.set(key, item()); } return m; }
      case 7: return info === 20 ? false : info === 21 ? true : null;
      default: throw new Error(`CBOR: unsupported major type ${major}`);
    }
  };
  const value = item();
  return { value, end: i };
}

/** The credential public key (COSE) inside authenticator data, which must carry attested credential data. */
function coseKeyFromAuthData(authData: Bytes): Map<Cbor, Cbor> {
  if (authData.length < 37 || !(authData[32] & 0x40)) throw new Error("authenticator data has no attested credential");
  const credIdLen = (authData[53] << 8) | authData[54];
  const { value } = decodeCbor(authData, 55 + credIdLen);
  if (!(value instanceof Map)) throw new Error("credential public key is not a COSE map");
  return value;
}

const bytes = (v: Cbor | undefined, what: string): Bytes => {
  if (!(v instanceof Uint8Array)) throw new Error(`COSE key: missing ${what}`);
  return v;
};

/**
 * Returns the passkey's public key as SPKI DER and its COSE algorithm, from a registration's attestationObject.
 * Supports EC2 P-256 (ES256, -7), OKP Ed25519 (EdDSA, -8) and RSA (RS256, -257): what HardState accepts.
 */
export async function publicKeyFromAttestation(attestationObject: Bytes): Promise<{ spki: Bytes; alg: number }> {
  const { value } = decodeCbor(attestationObject);
  if (!(value instanceof Map)) throw new Error("attestationObject is not a CBOR map");
  const key = coseKeyFromAuthData(bytes(value.get("authData"), "authData"));
  const kty = key.get(1), alg = Number(key.get(3));
  let jwk: JsonWebKey, imp: Parameters<typeof crypto.subtle.importKey>[2];
  if (kty === 2 && alg === -7) {
    if (key.get(-1) !== 1) throw new Error("COSE key: only the P-256 curve is supported");
    jwk = { kty: "EC", crv: "P-256", x: b64url.encode(bytes(key.get(-2), "x")), y: b64url.encode(bytes(key.get(-3), "y")) };
    imp = { name: "ECDSA", namedCurve: "P-256" };
  } else if (kty === 1 && alg === -8) {
    if (key.get(-1) !== 6) throw new Error("COSE key: only the Ed25519 curve is supported");
    jwk = { kty: "OKP", crv: "Ed25519", x: b64url.encode(bytes(key.get(-2), "x")) };
    imp = { name: "Ed25519" };
  } else if (kty === 3 && alg === -257) {
    jwk = { kty: "RSA", n: b64url.encode(bytes(key.get(-1), "n")), e: b64url.encode(bytes(key.get(-2), "e")), alg: "RS256" };
    imp = { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" };
  } else {
    throw new Error(`unsupported passkey algorithm (kty ${String(kty)}, alg ${alg})`);
  }
  const k = await crypto.subtle.importKey("jwk", jwk, imp, true, ["verify"]);
  return { spki: new Uint8Array((await crypto.subtle.exportKey("spki", k)) as ArrayBuffer), alg };
}
