// event.ts — the HSS-1 event: what an institution did, who signed it, which documents it touches, and where it sits in
// the institution's log. Its hash (sha256 over the RFC 8785 bytes) is what gets signed, chained and anchored.

import { b64url, concat, hex, randomBytes, sha256, utf8, type Bytes } from "./bytes.ts";
import { canonicalize, type Json } from "./canonical.ts";

export const HSS_VERSION = 1;

/** Event types the protocol itself interprets. Anything else (`case.open`, `permit.approve`…) is the issuer's own. */
export const SYSTEM_TYPES = {
  create: "issuer.create", keyAdd: "key.add", keyRevoke: "key.revoke", keyMove: "key.move", update: "issuer.update",
  sessionOpen: "session.open", sessionClose: "session.close", deptAdd: "dept.add", deptUpdate: "dept.update",
} as const;

export const isSystemType = (t: string) => (Object.values(SYSTEM_TYPES) as string[]).includes(t);
/** The protocol's own domains: no issuer vocabulary lives under them, known type or not. */
export const RESERVED_DOMAINS = ["issuer", "key", "session", "dept"] as const;
export const isReservedType = (t: string) => (RESERVED_DOMAINS as readonly string[]).includes(t.split(".")[0]);

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

/** What a key may sign: event types (exact, or a "domain.*" wildcard) and until when (ISO 8601). */
export interface KeyScope {
  types?: string[];
  expires?: string;
}

/**
 * A signing key as declared in issuer.create / key.add / session.open.
 * - admin: a person; manages keys. With `dept`, a department head: manages only that department's keys.
 * - official: a person; signs procedure steps.
 * - system: a process without a person (payment gateway, case system); always scoped to some types.
 * - session: a temporary key a person delegates to a device or system with session.open; signs on their behalf.
 */
export interface KeyInfo {
  /** Passkeys: the credential id (base64url). Ed25519 keys: "ed25519:" + first 16 bytes of sha256(spki), hex. */
  id: string;
  kind: "passkey" | "ed25519";
  /** COSE algorithm: -7 ES256, -257 RS256, -8 EdDSA. */
  alg: number;
  /** SubjectPublicKeyInfo DER, base64url. */
  publicKey: string;
  role: "admin" | "official" | "system" | "session";
  /** What it is, public: a person's title ("Building inspector"), never their name; a system's name ("Payments
   * gateway"); a session's device ("Front desk workstation"). The public sees a person as code + title + department. */
  label: string;
  /** People only: hex sha256("hardstate/holder/v1" ‖ salt ‖ name) (ids.ts). The name and salt stay with the institution,
   * which can reveal them to prove who held the key. */
  holder?: string;
  /** Passkeys only: the WebAuthn relying-party id the credential is bound to. */
  rpId?: string;
  /** Limits on what the key may sign. Required for system (types) and session (expires) keys. */
  scope?: KeyScope;
  /** The department it belongs to (a dept.add id); none = the institution itself. Sessions take their person's. */
  dept?: string;
}

/** A department as dept.add / dept.update declare it (public.dept). `types` limits what its keys may sign; `parent`
 * (dept.add only) nests it inside another department, up to DEPT_MAX_DEPTH levels. */
export interface DeptInfo {
  id: string;
  parent?: string;
  name?: string;
  types?: string[] | null;
  closed?: true;
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

const SLUG = /^[a-z0-9][a-z0-9-]{1,62}[a-z0-9]$/;
const TYPE = /^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$/;

/** Shape checks that do not need any state. Throws with the first problem. */
const FIELDS = new Set(["hss", "issuer", "seq", "prev", "type", "case", "ts", "public", "docs", "actor"]);

export function checkShape(e: HssEvent): void {
  const extra = Object.keys(e).filter((k) => !FIELDS.has(k));
  if (extra.length) throw new Error(`unknown event fields: ${extra.join(", ")}`);
  if (e.hss !== HSS_VERSION) throw new Error(`unsupported hss version ${e.hss}`);
  if (!SLUG.test(e.issuer)) throw new Error("issuer must be a lowercase slug (3-64 chars)");
  if (!Number.isSafeInteger(e.seq) || e.seq < 0) throw new Error("seq must be a non-negative integer");
  if (e.seq === 0 ? e.prev !== null : !/^[0-9a-f]{64}$/.test(e.prev ?? "")) throw new Error(e.seq === 0 ? "seq 0 must have prev null" : "prev must be a 32-byte hex hash");
  if (!TYPE.test(e.type)) throw new Error("type must look like 'domain.action'");
  if ((e.seq === 0) !== (e.type === SYSTEM_TYPES.create)) throw new Error("issuer.create is exactly the event at seq 0");
  if (e.case !== undefined && (typeof e.case !== "string" || !e.case || e.case.length > 128)) throw new Error("case must be a short string");
  if (Number.isNaN(Date.parse(e.ts))) throw new Error("ts must be an ISO 8601 date");
  if (typeof e.public !== "object" || e.public === null || Array.isArray(e.public)) throw new Error("public must be an object");
  if (!Array.isArray(e.docs) || e.docs.some((d) => !d.label || !/^[0-9a-f]{64}$/.test(d.commitment))) throw new Error("docs need a label and a 32-byte hex commitment");
  if (!e.actor) throw new Error("actor is required");
  if (canonicalize(e).length > 64 * 1024) throw new Error("event is larger than 64 KiB");
}
