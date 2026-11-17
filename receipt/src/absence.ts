// absence.ts — the HardState Proof of Absence: that, as of a given entry of an institution's log, the log held no
// record of some kind about some id (no human review of a decision, no revocation of a key, no record of a document).
//
// The operator keeps, per institution, a sorted index of keys. The index tree's leaves are the gaps between
// neighbouring keys, so one leaf whose bounds strictly contain a key proves that key is absent. The index root,
// bound to the log entry it describes, is a leaf (kind 0x04) of a batch, so it reaches Bitcoin like any record:
// once anchored, the answer cannot be changed afterwards. Anyone holding the full log can rebuild the index and check
// that the operator built it honestly.

import { concat, equal, hex, sha256, utf8, type Bytes } from "./bytes.ts";
import { rootFromSides, rootOf } from "./merkle.ts";
import { leafOf, proofRoot, type HardStateProof, type InclusionProof, type SidedStep } from "./proof.ts";
import { bitcoinSteps, type Step, type Verdict, type VerifyOptions } from "./verify.ts";

/** What an absence can be about: a human review of an AI decision (id: the decision's hash), a revocation of a key or
 * a closing of a session (id: the key id), the record of a document (id: its commitment). */
export type AbsenceKind = "review" | "revoke" | "doc";
export const ABSENCE_KINDS: readonly AbsenceKind[] = ["review", "revoke", "doc"];

const KEY_DOMAIN = utf8("hardstate/index/v1");
const LEAF_DOMAIN = utf8("hardstate/index-root/v1");

/** The index key: sha256("hardstate/index/v1" ‖ kind ‖ 0x00 ‖ id). */
export const indexKey = async (kind: AbsenceKind, id: string) => sha256(concat(KEY_DOMAIN, utf8(kind), new Uint8Array([0]), utf8(id)));

/** The bounds that close the index: below and above every key. */
export const LOW = new Uint8Array(32);
export const HIGH = new Uint8Array(32).fill(0xff);

export const compareBytes = (a: Bytes, b: Bytes) => {
  for (let i = 0; i < Math.min(a.length, b.length); i++) if (a[i] !== b[i]) return a[i] - b[i];
  return a.length - b.length;
};

/** The leaf for the gap (lo, hi). */
export const gapLeaf = (lo: Bytes, hi: Bytes) => leafOf("gap", concat(lo, hi));

/** The gap bounds of a set of keys, sorted and without duplicates: (LOW, k1), (k1, k2), …, (kn, HIGH). */
export function gaps(keys: Bytes[]): [Bytes, Bytes][] {
  const sorted = [...keys].sort(compareBytes).filter((k, i, a) => i === 0 || compareBytes(k, a[i - 1]) !== 0);
  const bounds = [LOW, ...sorted, HIGH];
  return bounds.slice(1).map((hi, i) => [bounds[i], hi]);
}

/** The index tree over a set of keys: its gaps, their leaves and its root. */
export async function indexTree(keys: Bytes[]) {
  const bounds = gaps(keys);
  const leaves = await Promise.all(bounds.map(([lo, hi]) => gapLeaf(lo, hi)));
  return { gaps: bounds, leaves, root: await rootOf(leaves) };
}

/** The data of the batch leaf (kind 0x04) that commits an index root to the log entry it describes. */
export async function indexLeafData(issuer: string, seq: number, headHash: Bytes, indexRoot: Bytes): Promise<Bytes> {
  const n = new Uint8Array(8);
  new DataView(n.buffer).setBigUint64(0, BigInt(seq));
  return sha256(concat(LEAF_DOMAIN, utf8(issuer), new Uint8Array([0]), n, headHash, indexRoot));
}

export interface AbsenceProof {
  hardstate: "absence";
  hss: 1;
  issuer: string;
  /** The log entry the index describes: everything up to and including it was indexed. */
  asOf: { seq: number; hash: string };
  query: { kind: AbsenceKind; id: string };
  /** The gap that contains the key, and its sided path to the index root. */
  gap: { lo: string; hi: string; path: SidedStep[] };
  index: { root: string };
  /** The index leaf's inclusion in its batch, and that batch on Bitcoin, as in a HardState Proof. */
  batch: InclusionProof & { id: string; closedAt: string };
  ots?: string;
  anchor?: HardStateProof["anchor"];
  issuedAt: string;
}

const msg = (e: unknown) => (e instanceof Error ? e.message : String(e));

const WHAT: Record<AbsenceKind, string> = {
  review: "no human review of this decision",
  revoke: "no revocation of this key",
  doc: "no record of this document",
};

/** Checks a Proof of Absence against Bitcoin, the same way a receipt is checked. */
export async function verifyAbsence(p: AbsenceProof, opts: VerifyOptions = {}): Promise<Verdict> {
  const steps: Step[] = [];
  const add = (s: Step) => { steps.push(s); return s; };
  let provenBefore: number | undefined;
  const seen = (t?: number) => { if (t && (provenBefore === undefined || t < provenBefore)) provenBefore = t; };

  if (p.hardstate !== "absence" || p.hss !== 1 || !ABSENCE_KINDS.includes(p.query?.kind)) {
    return { status: "invalid", subjectHash: "", steps: [{ id: "absence", state: "fail", title: "Not a HardState Proof of Absence", detail: "Unknown format or version." }] };
  }
  const key = await indexKey(p.query.kind, p.query.id);

  // 1. The key falls strictly inside a gap of the index, and that gap is in the index.
  let indexRoot: Bytes | undefined;
  try {
    const lo = hex.decode(p.gap.lo), hi = hex.decode(p.gap.hi);
    if (lo.length !== 32 || hi.length !== 32) throw new Error("gap bounds must be 32-byte hashes");
    if (!(compareBytes(lo, key) < 0 && compareBytes(key, hi) < 0)) throw new Error("the key is not inside this gap");
    const root = await rootFromSides(await gapLeaf(lo, hi), p.gap.path.map((x) => ({ s: x.s, h: hex.decode(x.h) })));
    if (!equal(root, hex.decode(p.index.root))) throw new Error("the gap is not in this index");
    indexRoot = root;
    add({ id: "absence", state: "pass", title: "Absent from the log",
      detail: `As of entry #${p.asOf.seq} of the institution's log, there was ${WHAT[p.query.kind]}.`,
      facts: { kind: p.query.kind, id: p.query.id, asOfSeq: p.asOf.seq, asOfHash: p.asOf.hash } });
  } catch (e) {
    add({ id: "absence", state: "fail", title: "Absence", detail: msg(e) });
  }

  // 2. The index, bound to that log entry, is a leaf of a batch.
  let batchRoot: Bytes | undefined;
  if (indexRoot) {
    try {
      const data = await indexLeafData(p.issuer, p.asOf.seq, hex.decode(p.asOf.hash), indexRoot);
      const root = await proofRoot(await leafOf("index", data), p.batch);
      if (!equal(root, hex.decode(p.batch.root))) throw new Error("the index is not in this batch");
      batchRoot = root;
      add({ id: "batch", state: "pass", title: "Included in batch", detail: `The index is in batch ${p.batch.id}.`, facts: { batch: p.batch.id, root: p.batch.root } });
    } catch (e) {
      add({ id: "batch", state: "fail", title: "Batch inclusion", detail: msg(e) });
    }
  }

  // 3. That batch on Bitcoin.
  await bitcoinSteps(batchRoot, p, opts, add, seen);

  const failed = steps.some((s) => s.state === "fail");
  const onChain = steps.some((s) => (s.id === "ots" || (s.id === "anchor" && p.anchor?.network === "bitcoin")) && s.state === "pass");
  return { status: failed ? "invalid" : onChain ? "valid" : "pending", steps, provenBefore, subjectHash: hex.encode(key) };
}
