// checkpoint.ts — HardState Log Checkpoints: a signed statement of an institution's log at one size: its MMR root
// (mmr.ts) and its head. A verifier that holds an earlier checkpoint checks that the log only grew (a consistency
// proof), and that a record is in it (an inclusion proof), without replaying a single entry.
//
// The operator signs checkpoints with its key (the one at /v1/operator) over a domain-separated hash
// ("hardstate/checkpoint/v1" ‖ JCS(checkpoint)), so a checkpoint's signature can never pass as an event's, a report's
// or an operator request's. Independent witnesses (other institutions) add their own signatures over the same hash.

import { concat, hex, sha256, utf8, type Bytes } from "./bytes.ts";
import { canonicalize } from "./canonical.ts";
import type { KeyInfo, Signature } from "./event.ts";
import type { Sided } from "./merkle.ts";
import { verifyConsistency, verifyMmrInclusion, type ConsistencyProof } from "./mmr.ts";
import { verifyHashSignature } from "./sig.ts";

const CHECKPOINT_DOMAIN = utf8("hardstate/checkpoint/v1");

export interface Checkpoint {
  hardstate: "checkpoint";
  v: 1;
  issuer: string;
  /** Entries in the log: head.seq + 1. */
  size: number;
  /** MMR root over the log's entries (hex). */
  root: string;
  head: { seq: number; hash: string };
  ts: string;
  /** Id of the key that signs it (the operator's, /v1/operator). */
  signer: string;
}

/** A signature over the checkpoint hash: the operator's, then any witnesses'. */
export interface CheckpointSignature { key: string; sig: Signature }

export interface SignedCheckpoint { checkpoint: Checkpoint; sigs: CheckpointSignature[] }

export const checkpointHash = async (c: Checkpoint): Promise<Bytes> => sha256(concat(CHECKPOINT_DOMAIN, utf8(canonicalize(c as unknown as Parameters<typeof canonicalize>[0]))));

/** Checks the operator's signature on a checkpoint and that its head is the last entry under its root. */
export async function verifyCheckpoint(s: SignedCheckpoint, operatorKey: KeyInfo, headPath?: { s: "L" | "R"; h: string }[]): Promise<string> {
  const c = s.checkpoint;
  if (c.hardstate !== "checkpoint" || c.v !== 1) throw new Error("not a HardState checkpoint");
  if (c.size !== c.head.seq + 1) throw new Error("a checkpoint's size is its head seq + 1");
  if (c.signer !== operatorKey.id) throw new Error(`signed by ${c.signer}, not by the operator key ${operatorKey.id}`);
  const sig = s.sigs.find((x) => x.key === operatorKey.id);
  if (!sig) throw new Error("the operator's signature is missing");
  const h = await checkpointHash(c);
  await verifyHashSignature(h, sig.sig, operatorKey, "checkpoint");
  if (headPath && !(await verifyMmrInclusion(hex.decode(c.head.hash), toSided(headPath), hex.decode(c.root)))) throw new Error("the head is not under the checkpoint's root");
  return hex.encode(h);
}

/** Checks that checkpoint `b` extends checkpoint `a` of the same log (same entries, more of them). */
export async function verifyCheckpoints(a: Checkpoint, b: Checkpoint, proof: ConsistencyProof): Promise<boolean> {
  if (a.issuer !== b.issuer || proof.from !== a.size || proof.to !== b.size) return false;
  if (a.size === b.size) return a.root === b.root && a.head.hash === b.head.hash;
  return verifyConsistency(proof, hex.decode(a.root), hex.decode(b.root));
}

/** Checks that a record (by its hash) is in the log of a checkpoint. */
export async function verifyInCheckpoint(c: Checkpoint, eventHash: string, path: { s: "L" | "R"; h: string }[]): Promise<boolean> {
  return verifyMmrInclusion(hex.decode(eventHash), toSided(path), hex.decode(c.root));
}

const toSided = (p: { s: "L" | "R"; h: string }[]): Sided[] => p.map((x) => ({ s: x.s, h: hex.decode(x.h) }));

