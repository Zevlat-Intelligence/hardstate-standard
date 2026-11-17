// layered.ts — L3 of the layered log: a witnessed checkpoint of an institution's log (checkpoint.ts, witness.ts) is one
// leaf (kind 0x07) of a batch, so the batch's OpenTimestamps proof and HardState Anchor seal every record under it.
//
// A record's receipt then goes: record → its institution's log at the checkpoint (an MMR inclusion path, mmr.ts) →
// the checkpoint's leaf in the batch (a sided path) → the batch on Bitcoin. The leaf commits to the checkpoint and to
// the exact set of witness cosignatures it had when it was batched, so the witnessing is sealed with it.

import { concat, equal, hex, sha256, utf8, type Bytes } from "./bytes.ts";
import { canonicalize, type Json } from "./canonical.ts";
import { checkpointHash, verifyCheckpoint, type SignedCheckpoint } from "./checkpoint.ts";
import type { KeyInfo } from "./event.ts";
import type { Sided } from "./merkle.ts";
import { verifyMmrInclusion } from "./mmr.ts";
import { leafOf, proofRoot, type InclusionProof, type SidedStep } from "./proof.ts";
import { verifyWitnessed, type Cosignature, type WitnessKey } from "./witness.ts";

const COSIGS_DOMAIN = utf8("hardstate/cosigs/v1");
const LEAF_DOMAIN = utf8("hardstate/checkpoint-leaf/v1");

/** What a receipt carries on the layered log, in place of a per-record batch path. */
export interface CheckpointInclusion {
  signed: SignedCheckpoint;
  /** The cosignatures the checkpoint had when it was batched: exactly the set its leaf commits to. */
  cosigs: Cosignature[];
  /** The witnesses' public keys, as each declared it in its own institution's log. */
  witnessKeys?: WitnessKey[];
  /** The Bitcoin block that chose the witnesses, and whom it chose. */
  witnesses?: { height: number; blockHash: string; selected: string[] };
  /** The record's sided path to the checkpoint's MMR root. */
  path: SidedStep[];
  /** The checkpoint leaf's place in its batch. */
  batch: InclusionProof & { id: string; closedAt: string };
}

/** The commitment to a set of cosignatures: order-free (sorted by witness, then key). */
export async function cosigSetHash(cosigs: Cosignature[]): Promise<Bytes> {
  const sorted = [...cosigs].sort((a, b) => (a.witness < b.witness ? -1 : a.witness > b.witness ? 1 : a.key < b.key ? -1 : a.key > b.key ? 1 : 0));
  return sha256(concat(COSIGS_DOMAIN, utf8(canonicalize(sorted as unknown as Json))));
}

/** The data of a checkpoint's batch leaf (kind 0x07): sha256("hardstate/checkpoint-leaf/v1" ‖ checkpoint hash ‖ cosig set hash). */
export async function checkpointLeafData(signed: SignedCheckpoint, cosigs: Cosignature[]): Promise<Bytes> {
  return sha256(concat(LEAF_DOMAIN, await checkpointHash(signed.checkpoint), await cosigSetHash(cosigs)));
}

export interface CheckpointResult {
  /** The batch root the checkpoint leaf leads to: what OpenTimestamps and the HardState Anchor then prove. */
  batchRoot: Bytes;
  /** Institutions whose cosignatures verified (when the receipt carries their keys). */
  witnesses: string[];
  operatorChecked: boolean;
}

/**
 * Checks the layered path of a record: it is in its institution's log at the checkpoint, and the checkpoint (with its
 * cosignature set) is a leaf of the batch. With `operatorKey`, also the operator's signature on the checkpoint; with
 * witness keys in the receipt, the cosignatures (at least `k` distinct institutions, chosen by the block when it says
 * so). Throws with the first problem.
 */
export async function verifyCheckpointInclusion(recordHash: Bytes, issuer: string, ci: CheckpointInclusion,
  opts: { operatorKey?: KeyInfo; k?: number } = {}): Promise<CheckpointResult> {
  const c = ci.signed?.checkpoint;
  if (!c || c.hardstate !== "checkpoint" || c.v !== 1) throw new Error("not a HardState checkpoint");
  if (c.issuer !== issuer) throw new Error("the checkpoint is of another institution's log");
  const path: Sided[] = ci.path.map((x) => ({ s: x.s, h: hex.decode(x.h) }));
  if (!(await verifyMmrInclusion(recordHash, path, hex.decode(c.root)))) throw new Error("the record is not in the log at this checkpoint");
  let operatorChecked = false;
  if (opts.operatorKey) { await verifyCheckpoint(ci.signed, opts.operatorKey); operatorChecked = true; }
  let witnesses: string[] = [];
  if (ci.witnessKeys?.length) {
    const w = await verifyWitnessed(c, ci.cosigs, ci.witnessKeys, opts.k ?? 1, ci.witnesses?.selected);
    if (w.rejected.length) throw new Error(`a cosignature does not verify: ${w.rejected[0].witness} (${w.rejected[0].reason})`);
    witnesses = [...w.witnesses].sort();
  }
  const root = await proofRoot(await leafOf("checkpoint", await checkpointLeafData(ci.signed, ci.cosigs)), ci.batch);
  if (!equal(root, hex.decode(ci.batch.root))) throw new Error("the checkpoint is not in this batch");
  return { batchRoot: root, witnesses, operatorChecked };
}
