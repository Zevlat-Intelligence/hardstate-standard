// witness.ts — L2 of the layered log: other institutions witness an institution's checkpoints (checkpoint.ts).
//
// A witness checks that a new checkpoint extends the last one it signed (a consistency proof), then signs
// sha256("hardstate/witness/v1" ‖ JCS({ issuer, size, root })). It signs outside the log: no institution ever writes
// another's hash into its own log. Witnesses are chosen pseudo-randomly from a Bitcoin block hash the institution
// cannot pick, so it cannot choose friendly witnesses; anyone can recompute the choice.
//
// Two signed checkpoints of the same log and size with different roots (or heads) are a proof of a fork
// (equivocation): an institution or operator that showed two histories is caught with its own signatures.

import { concat, hex, sha256, utf8, type Bytes } from "./bytes.ts";
import { canonicalize } from "./canonical.ts";
import { checkpointHash, type Checkpoint, type SignedCheckpoint } from "./checkpoint.ts";
import type { KeyInfo, Signature } from "./event.ts";
import { verifyHashSignature } from "./sig.ts";

const WITNESS_DOMAIN = utf8("hardstate/witness/v1");
const SELECT_DOMAIN = utf8("hardstate/witness-select/v1");

/** The event type a witness key is scoped to in its own institution's log. It never signs a log event. */
export const WITNESS_TYPE = "witness.cosign";

/** The hash a witness signs for a checkpoint: only what it checked, the log's identity, size and root. */
export const witnessHash = async (c: Pick<Checkpoint, "issuer" | "size" | "root">): Promise<Bytes> =>
  sha256(concat(WITNESS_DOMAIN, utf8(canonicalize({ issuer: c.issuer, size: c.size, root: c.root }))));

/** A witness's cosignature: which institution witnessed, with which of its keys. */
export interface Cosignature { witness: string; key: string; sig: Signature; ts: string }

/** A witness key as a verifier knows it: the institution that holds it and the key itself. */
export interface WitnessKey { issuer: string; info: KeyInfo }

/** Which `k` of `candidates` (institution ids) witness `issuer`'s checkpoints after block `blockHash`: ranked by
 * sha256(sha256("hardstate/witness-select/v1" ‖ blockHash ‖ issuer) ‖ candidate). The issuer never witnesses itself. */
export async function selectWitnesses(blockHash: string, issuer: string, candidates: string[], k: number): Promise<string[]> {
  const seed = await sha256(concat(SELECT_DOMAIN, hex.decode(blockHash), utf8(issuer)));
  const pool = [...new Set(candidates)].filter((c) => c !== issuer);
  const scored = await Promise.all(pool.map(async (c) => ({ c, s: hex.encode(await sha256(concat(seed, utf8(c)))) })));
  return scored.sort((a, b) => (a.s < b.s ? -1 : a.s > b.s ? 1 : 0)).slice(0, Math.max(0, k)).map((x) => x.c);
}

/** Checks one cosignature against a known witness key. Throws with the reason. */
export async function verifyCosignature(c: Checkpoint, cs: Cosignature, key: WitnessKey): Promise<void> {
  if (cs.key !== key.info.id) throw new Error(`cosignature by ${cs.key}, not by ${key.info.id}`);
  if (cs.witness !== key.issuer) throw new Error(`the key ${cs.key} belongs to ${key.issuer}, not ${cs.witness}`);
  if (cs.witness === c.issuer) throw new Error("an institution cannot witness its own log");
  await verifyHashSignature(await witnessHash(c), cs.sig, key.info, "cosignature");
}

export interface Witnessed {
  /** Institutions whose cosignatures verified (one each). */
  witnesses: string[];
  /** Cosignatures that did not verify, with why. */
  rejected: { witness: string; key: string; reason: string }[];
  /** At least `k` distinct institutions, all of them in `selected` when given. */
  ok: boolean;
}

/** Checks a checkpoint's cosignatures: how many distinct institutions witnessed it, against their known keys. With
 * `selected`, only those institutions count (the ones the block hash chose). */
export async function verifyWitnessed(c: Checkpoint, cosigs: Cosignature[], keys: WitnessKey[], k: number, selected?: string[]): Promise<Witnessed> {
  const byId = new Map(keys.map((x) => [x.info.id, x]));
  const witnesses = new Set<string>();
  const rejected: Witnessed["rejected"] = [];
  for (const cs of cosigs) {
    try {
      const key = byId.get(cs.key);
      if (!key) throw new Error("unknown witness key");
      if (selected && !selected.includes(cs.witness)) throw new Error("not one of the witnesses the block chose");
      await verifyCosignature(c, cs, key);
      witnesses.add(cs.witness);
    } catch (e) {
      rejected.push({ witness: cs.witness, key: cs.key, reason: e instanceof Error ? e.message : String(e) });
    }
  }
  return { witnesses: [...witnesses], rejected, ok: witnesses.size >= k };
}

/** Evidence that one log showed two histories: two checkpoints of the same institution and size that disagree, each
 * with a signature from the same signer (the operator, or a witness that signed both). */
export interface Equivocation {
  hardstate: "equivocation";
  v: 1;
  issuer: string;
  size: number;
  a: SignedCheckpoint;
  b: SignedCheckpoint;
  /** The key whose two signatures prove it; the verifier is given that key. */
  key: string;
}

/** Checks a proof of fork: same log, same size, different root or head, both signed by `key` (over the checkpoint
 * hash, or over the witness hash when `key` is a witness's). Returns what differs. */
export async function verifyEquivocation(e: Equivocation, key: KeyInfo): Promise<{ root: boolean; head: boolean }> {
  const { a, b } = e;
  const ca = a.checkpoint, cb = b.checkpoint;
  if (ca.issuer !== e.issuer || cb.issuer !== e.issuer) throw new Error("the checkpoints are of another log");
  if (ca.size !== e.size || cb.size !== e.size) throw new Error("the checkpoints are not of the same size");
  const differs = { root: ca.root !== cb.root, head: ca.head.hash !== cb.head.hash || ca.head.seq !== cb.head.seq };
  if (!differs.root && !differs.head) throw new Error("the checkpoints agree: no fork");
  if (key.id !== e.key) throw new Error(`evidence names ${e.key}, not ${key.id}`);
  for (const s of [a, b]) {
    const sig = s.sigs.find((x) => x.key === key.id);
    if (!sig) throw new Error(`a checkpoint lacks a signature by ${key.id}`);
    const h = s.checkpoint.signer === key.id ? await checkpointHash(s.checkpoint) : await witnessHash(s.checkpoint);
    await verifyHashSignature(h, sig.sig, key, "checkpoint");
  }
  return differs;
}

/** True when two signed checkpoints of the same log and size disagree: what an equivocation monitor stores. */
export const conflicting = (a: Checkpoint, b: Checkpoint) =>
  a.issuer === b.issuer && a.size === b.size && (a.root !== b.root || a.head.hash !== b.head.hash);
