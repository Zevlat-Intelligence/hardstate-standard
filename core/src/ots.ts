// ots.ts — OpenTimestamps, enough of it to stamp, upgrade and verify without a Node dependency.
//
// A timestamp is a tree: from a message, each op (append, prepend, sha256…) leads to a new message with its own
// timestamp, and attestations hang off the nodes. A Bitcoin attestation says "this node's message is the merkle root of
// block N"; a pending one says "calendar X promised to put this message in a block; ask it later". The wire format is
// the reference client's (python-opentimestamps), so a `.ots` written here verifies with `ots verify` and vice versa.
//
// Calendars speak plain HTTP: POST <cal>/digest with the 32 raw bytes returns a timestamp for them; once the calendar's
// transaction confirms, GET <cal>/timestamp/<hex of the pending message> returns the rest of the path.

import { ripemd160 } from "@noble/hashes/legacy.js";
import { keccak_256 } from "@noble/hashes/sha3.js";
import { compare, concat, equal, hex, randomBytes, reverse, sha256, utf8, type Bytes } from "./bytes.ts";

export const HEADER_MAGIC = concat(
  new Uint8Array([0x00]), utf8("OpenTimestamps"), new Uint8Array([0x00, 0x00]), utf8("Proof"),
  new Uint8Array([0x00, 0xbf, 0x89, 0xe2, 0xe8, 0x84, 0xe8, 0x92, 0x94]),
);
const MAJOR_VERSION = 1;
const MAX_MSG = 4096;

const TAG = {
  pending: Uint8Array.from([0x83, 0xdf, 0xe3, 0x0d, 0x2e, 0xf9, 0x0c, 0x8e]),
  bitcoin: Uint8Array.from([0x05, 0x88, 0x96, 0x0d, 0x73, 0xd7, 0x19, 0x01]),
};

const OP = { sha1: 0x02, ripemd160: 0x03, sha256: 0x08, keccak256: 0x67, append: 0xf0, prepend: 0xf1, reverse: 0xf2, hexlify: 0xf3 } as const;

export type Attestation =
  | { kind: "pending"; uri: string }
  | { kind: "bitcoin"; height: number }
  | { kind: "unknown"; tag: Bytes; payload: Bytes };

export type Op = { tag: number; arg?: Bytes };

export interface Timestamp {
  msg: Bytes;
  attestations: Attestation[];
  ops: { op: Op; ts: Timestamp }[];
}

export const newTimestamp = (msg: Bytes): Timestamp => ({ msg, attestations: [], ops: [] });

// ── ops ───────────────────────────────────────────────────────────────────────────────────────────────────────────

export async function applyOp(op: Op, msg: Bytes): Promise<Bytes> {
  let out: Bytes;
  switch (op.tag) {
    case OP.append: out = concat(msg, op.arg!); break;
    case OP.prepend: out = concat(op.arg!, msg); break;
    case OP.sha256: out = await sha256(msg); break;
    case OP.reverse: out = reverse(msg); break;
    case OP.hexlify: out = utf8(hex.encode(msg)); break;
    // Older proofs (and Bitcoin's own HASH160 history) use these; the reference client accepts all of them.
    case OP.ripemd160: out = Uint8Array.from(ripemd160(msg)); break;
    case OP.sha1: out = new Uint8Array(await crypto.subtle.digest("SHA-1", msg)); break;
    case OP.keccak256: out = Uint8Array.from(keccak_256(msg)); break;
    default: throw new Error(`OTS: unsupported op 0x${op.tag.toString(16)}`);
  }
  if (out.length > MAX_MSG) throw new Error("OTS: message too long");
  return out;
}

const opKey = (op: Op) => `${op.tag}:${op.arg ? hex.encode(op.arg) : ""}`;
const opCmp = (a: Op, b: Op) => a.tag - b.tag || compare(a.arg ?? new Uint8Array(), b.arg ?? new Uint8Array());

/** Adds `op` under `ts` (or returns the existing branch), the way the reference client's `ts.ops.add(op)` does. */
export async function addOp(ts: Timestamp, op: Op): Promise<Timestamp> {
  const found = ts.ops.find((o) => opKey(o.op) === opKey(op));
  if (found) return found.ts;
  const child = newTimestamp(await applyOp(op, ts.msg));
  ts.ops.push({ op, ts: child });
  return child;
}

/** Merges `other` (a timestamp for the same message) into `ts`. */
export function merge(ts: Timestamp, other: Timestamp): void {
  if (!equal(ts.msg, other.msg)) throw new Error("OTS: can only merge timestamps for the same message");
  for (const a of other.attestations) if (!ts.attestations.some((b) => attKey(a) === attKey(b))) ts.attestations.push(a);
  for (const { op, ts: sub } of other.ops) {
    const mine = ts.ops.find((o) => opKey(o.op) === opKey(op));
    if (mine) merge(mine.ts, sub); else ts.ops.push({ op, ts: sub });
  }
}

// ── wire format ───────────────────────────────────────────────────────────────────────────────────────────────────

class Writer {
  private parts: number[] = [];
  byte(b: number) { this.parts.push(b); }
  bytes(b: Bytes) { for (const x of b) this.parts.push(x); }
  varuint(n: number) {
    if (n === 0) { this.byte(0); return; }
    while (n > 0) { const b = n & 0x7f; n = Math.floor(n / 128); this.byte(n > 0 ? b | 0x80 : b); }
  }
  varbytes(b: Bytes) { this.varuint(b.length); this.bytes(b); }
  out() { return Uint8Array.from(this.parts); }
}

class Reader {
  i = 0;
  private b: Bytes;
  constructor(b: Bytes) { this.b = b; }
  byte() { if (this.i >= this.b.length) throw new Error("OTS: truncated"); return this.b[this.i++]; }
  bytes(n: number) { if (this.i + n > this.b.length) throw new Error("OTS: truncated"); const o = this.b.slice(this.i, this.i + n); this.i += n; return o; }
  varuint() { let n = 0, shift = 1; for (;;) { const b = this.byte(); n += (b & 0x7f) * shift; if (!(b & 0x80)) return n; shift *= 128; } }
  varbytes(max = MAX_MSG) { const n = this.varuint(); if (n > max) throw new Error("OTS: varbytes too long"); return this.bytes(n); }
  done() { return this.i === this.b.length; }
}

function attPayload(a: Attestation): { tag: Bytes; payload: Bytes } {
  const w = new Writer();
  if (a.kind === "pending") { w.varbytes(utf8(a.uri)); return { tag: TAG.pending, payload: w.out() }; }
  if (a.kind === "bitcoin") { w.varuint(a.height); return { tag: TAG.bitcoin, payload: w.out() }; }
  return { tag: a.tag, payload: a.payload };
}
const attKey = (a: Attestation) => { const { tag, payload } = attPayload(a); return hex.encode(tag) + hex.encode(payload); };
const attCmp = (a: Attestation, b: Attestation) => { const x = attPayload(a), y = attPayload(b); return compare(x.tag, y.tag) || compare(x.payload, y.payload); };

function writeAttestation(w: Writer, a: Attestation) {
  const { tag, payload } = attPayload(a);
  w.bytes(tag);
  w.varbytes(payload);
}

function readAttestation(r: Reader): Attestation {
  const tag = r.bytes(8);
  const payload = r.varbytes(8192);
  const p = new Reader(payload);
  if (equal(tag, TAG.pending)) {
    const uri = new TextDecoder().decode(p.varbytes(1000));
    if (!/^[a-zA-Z0-9.\-_/:]+$/.test(uri)) throw new Error("OTS: pending attestation URI has illegal characters");
    return { kind: "pending", uri };
  }
  if (equal(tag, TAG.bitcoin)) return { kind: "bitcoin", height: p.varuint() };
  return { kind: "unknown", tag, payload };
}

function writeOp(w: Writer, op: Op) {
  w.byte(op.tag);
  if (op.tag === OP.append || op.tag === OP.prepend) w.varbytes(op.arg!);
}

export function writeTimestamp(w: Writer, ts: Timestamp): void {
  if (!ts.attestations.length && !ts.ops.length) throw new Error("OTS: empty timestamp");
  const atts = [...ts.attestations].sort(attCmp);
  const ops = [...ts.ops].sort((a, b) => opCmp(a.op, b.op));
  const items: (() => void)[] = [
    ...atts.map((a) => () => { w.byte(0x00); writeAttestation(w, a); }),
    ...ops.map(({ op, ts: sub }) => () => { writeOp(w, op); writeTimestamp(w, sub); }),
  ];
  items.forEach((item, i) => { if (i < items.length - 1) w.byte(0xff); item(); });
}

async function readTimestamp(r: Reader, msg: Bytes, depth = 0): Promise<Timestamp> {
  if (depth > 256) throw new Error("OTS: recursion limit");
  const ts = newTimestamp(msg);
  const item = async (tag: number) => {
    if (tag === 0x00) { ts.attestations.push(readAttestation(r)); return; }
    const op: Op = { tag };
    if (tag === OP.append || tag === OP.prepend) op.arg = r.varbytes();
    ts.ops.push({ op, ts: await readTimestamp(r, await applyOp(op, msg), depth + 1) });
  };
  let tag = r.byte();
  while (tag === 0xff) { await item(r.byte()); tag = r.byte(); }
  await item(tag);
  return ts;
}

export function serializeTimestamp(ts: Timestamp): Bytes {
  const w = new Writer();
  writeTimestamp(w, ts);
  return w.out();
}

export async function deserializeTimestamp(bytes: Bytes, msg: Bytes): Promise<Timestamp> {
  const r = new Reader(bytes);
  const ts = await readTimestamp(r, msg);
  if (!r.done()) throw new Error("OTS: trailing bytes");
  return ts;
}

/** A detached `.ots` file: magic, version, the file-hash op (sha256 here) and digest, then the timestamp. */
export function serializeDetached(ts: Timestamp): Bytes {
  const w = new Writer();
  w.bytes(HEADER_MAGIC);
  w.varuint(MAJOR_VERSION);
  w.byte(OP.sha256);
  w.bytes(ts.msg);
  writeTimestamp(w, ts);
  return w.out();
}

export async function deserializeDetached(bytes: Bytes): Promise<Timestamp> {
  const r = new Reader(bytes);
  if (!equal(r.bytes(HEADER_MAGIC.length), HEADER_MAGIC)) throw new Error("OTS: not an OpenTimestamps proof");
  if (r.varuint() !== MAJOR_VERSION) throw new Error("OTS: unsupported major version");
  if (r.byte() !== OP.sha256) throw new Error("OTS: only sha256 file digests are supported");
  const ts = await readTimestamp(r, r.bytes(32));
  if (!r.done()) throw new Error("OTS: trailing bytes");
  return ts;
}

// ── walking ───────────────────────────────────────────────────────────────────────────────────────────────────────

/** Every attestation in the tree with the message it attests and the ops that lead there from the root. */
export function* attestations(ts: Timestamp, path: Op[] = []): Generator<{ msg: Bytes; att: Attestation; path: Op[] }> {
  for (const att of ts.attestations) yield { msg: ts.msg, att, path };
  for (const { op, ts: sub } of ts.ops) yield* attestations(sub, [...path, op]);
}

export type OtsStatus = "pending" | "confirmed";
export const otsStatus = (ts: Timestamp): OtsStatus => ([...attestations(ts)].some((a) => a.att.kind === "bitcoin") ? "confirmed" : "pending");

// ── calendars ─────────────────────────────────────────────────────────────────────────────────────────────────────

/** The public aggregation pools (they return pending attestations naming the calendars that will commit). */
export const DEFAULT_CALENDARS = [
  "https://a.pool.opentimestamps.org",
  "https://b.pool.opentimestamps.org",
  "https://a.pool.eternitywall.com",
  "https://ots.btc.catallaxy.com",
];

/** Calendar hosts we are willing to contact when upgrading (a proof names its own URIs; never fetch arbitrary ones). */
export const CALENDAR_ALLOWLIST = [
  /^https:\/\/[a-z0-9-]+\.calendar\.opentimestamps\.org$/,
  /^https:\/\/[a-z0-9-]+\.pool\.opentimestamps\.org$/,
  /^https:\/\/[a-z0-9.-]*calendar\.eternitywall\.com$/,
  /^https:\/\/[a-z0-9.-]*pool\.eternitywall\.com$/,
  /^https:\/\/[a-z0-9.-]*calendar\.catallaxy\.com$/,
  /^https:\/\/ots\.btc\.catallaxy\.com$/,
];

const HEADERS = { Accept: "application/vnd.opentimestamps.v1", "User-Agent": "hardstate/0.1" };

type Fetch = typeof fetch;

/**
 * Stamps `digest` (the batch root): append a 16-byte nonce and sha256, as the reference client does, so a calendar
 * never sees the root itself; then submit that to every calendar and merge their answers. Needs `min` successes.
 */
export async function stamp(digest: Bytes, opts: { calendars?: string[]; min?: number; fetch?: Fetch; timeoutMs?: number } = {}): Promise<Timestamp> {
  const { calendars = DEFAULT_CALENDARS, min = 2, timeoutMs = 10_000 } = opts;
  const f = opts.fetch ?? fetch;
  const root = newTimestamp(digest);
  const nonced = await addOp(root, { tag: OP.append, arg: randomBytes(16) });
  const commit = await addOp(nonced, { tag: OP.sha256 });
  const results = await Promise.allSettled(calendars.map(async (cal) => {
    const res = await f(`${cal}/digest`, { method: "POST", body: commit.msg, headers: HEADERS, signal: AbortSignal.timeout(timeoutMs) });
    if (!res.ok) throw new Error(`${cal}: HTTP ${res.status}`);
    return deserializeTimestamp(new Uint8Array(await res.arrayBuffer()), commit.msg);
  }));
  const ok = results.flatMap((r) => (r.status === "fulfilled" ? [r.value] : []));
  if (ok.length < min) {
    const why = results.flatMap((r) => (r.status === "rejected" ? [String(r.reason?.message ?? r.reason)] : []));
    throw new Error(`OTS: only ${ok.length}/${calendars.length} calendars answered (${why.join("; ")})`);
  }
  for (const t of ok) merge(commit, t);
  return root;
}

/**
 * Asks each pending attestation's calendar for the completed path and grafts it in place. Returns how many branches
 * were upgraded. Calendars outside CALENDAR_ALLOWLIST are skipped.
 */
export async function upgrade(ts: Timestamp, opts: { fetch?: Fetch; timeoutMs?: number } = {}): Promise<number> {
  const f = opts.fetch ?? fetch;
  let upgraded = 0;
  const walk = async (node: Timestamp): Promise<void> => {
    for (const att of [...node.attestations]) {
      if (att.kind !== "pending" || !CALENDAR_ALLOWLIST.some((re) => re.test(att.uri))) continue;
      try {
        const res = await f(`${att.uri}/timestamp/${hex.encode(node.msg)}`, { headers: HEADERS, signal: AbortSignal.timeout(opts.timeoutMs ?? 10_000) });
        if (res.status === 404) continue; // not yet in a block
        if (!res.ok) continue;
        const more = await deserializeTimestamp(new Uint8Array(await res.arrayBuffer()), node.msg);
        if (![...attestations(more)].some((a) => a.att.kind === "bitcoin")) continue;
        merge(node, more);
        node.attestations = node.attestations.filter((a) => a !== att);
        upgraded++;
      } catch { /* a calendar being down only delays the upgrade */ }
    }
    for (const { ts: sub } of node.ops) await walk(sub);
  };
  await walk(ts);
  return upgraded;
}

/** For a Bitcoin attestation, the attested message must equal the block's merkle root in the header's byte order. */
export const merkleRootMatches = (attestedMsg: Bytes, merkleRootDisplayHex: string) =>
  attestedMsg.length === 32 && equal(attestedMsg, reverse(hex.decode(merkleRootDisplayHex)));
