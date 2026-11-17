// event.ts — the record: what an institution did, who signed it, which documents it touches, and where it sits in the
// institution's log. Its hash (sha256 over the RFC 8785 bytes) is what gets signed, chained and anchored.

import { b64url, concat, hex, randomBytes, sha256, utf8, type Bytes } from "./bytes.ts";
import { canonicalize, type Json } from "./canonical.ts";

export const HSS_VERSION = 1;

export interface DocRef {
  /** Human label, public: "Site plan", "Inspection report". */
  label: string;
  /** hex sha256("hardstate/doc/v1" ‖ salt ‖ sha256(file)). The salt stays with the holder unless the doc is public. */
  commitment: string;
  mime?: string;
  size?: number;
}

export interface HssEvent {
  hss: 1;
  /** Issuer id: lowercase slug, stable for the life of the log. */
  issuer: string;
  /** 0 for issuer.create, then +1 per event. */
  seq: number;
  /** hex hash of the event at seq-1; null only at seq 0. */
  prev: string | null;
  type: string;
  /** Optional case / file / procedure reference this event belongs to. */
  case?: string;
  /** When the issuer says it happened (ISO 8601). The Bitcoin anchor bounds it from above. */
  ts: string;
  /** Public metadata. Transparency by default: whatever is here is published. */
  public: { [k: string]: Json };
  docs: DocRef[];
  /** Key id of the signer (see KeyInfo.id). */
  actor: string;
}

export type Signature =
  | { kind: "passkey"; authenticatorData: string; clientDataJSON: string; signature: string }
  | { kind: "ed25519"; signature: string };

export interface SignedEvent {
  event: HssEvent;
  sig: Signature;
}

/** Limits the issuer attaches to a key. */
export interface KeyScope {
  types?: string[];
  expires?: string;
}

/** A signing key as a record declares it in `public.key`. */
export interface KeyInfo {
  /** Passkeys: the credential id (base64url). Ed25519 keys: "ed25519:" + first 16 bytes of sha256(spki), hex. */
  id: string;
  kind: "passkey" | "ed25519";
  /** COSE algorithm: -7 ES256, -257 RS256, -8 EdDSA. */
  alg: number;
  /** SubjectPublicKeyInfo DER, base64url. */
  publicKey: string;
  role: "admin" | "official" | "system" | "session";
  /** What the key is, public: a title or a system's name, never a person's name. */
  label: string;
  /** A salted commitment the institution may open to show who held the key. */
  holder?: string;
  /** Passkeys only: the WebAuthn relying-party id the credential is bound to. */
  rpId?: string;
  scope?: KeyScope;
  dept?: string;
}


export const eventBytes = (e: HssEvent) => utf8(canonicalize(e));
export const eventHash = async (e: HssEvent) => sha256(eventBytes(e));
export const eventHashHex = async (e: HssEvent) => hex.encode(await eventHash(e));

/** The WebAuthn challenge a passkey signs for this event: the event hash, base64url, as clientDataJSON carries it. */
export const eventChallenge = async (e: HssEvent) => b64url.encode(await eventHash(e));

const DOC_DOMAIN = utf8("hardstate/doc/v1");

export async function docCommitment(fileDigest: Bytes, salt: Bytes): Promise<Bytes> {
  if (fileDigest.length !== 32 || salt.length !== 32) throw new Error("doc commitment needs a 32-byte digest and salt");
  return sha256(concat(DOC_DOMAIN, salt, fileDigest));
}

/** Hash a file and commit to it with a fresh salt. Keep the salt: without it nobody can match the file to the event. */
export async function commitFile(file: Bytes): Promise<{ digest: string; salt: string; commitment: string }> {
  const digest = await sha256(file);
  const salt = randomBytes(32);
  return { digest: hex.encode(digest), salt: hex.encode(salt), commitment: hex.encode(await docCommitment(digest, salt)) };
}

export async function ed25519KeyId(spki: Bytes): Promise<string> {
  return `ed25519:${hex.encode((await sha256(spki)).slice(0, 16))}`;
}
