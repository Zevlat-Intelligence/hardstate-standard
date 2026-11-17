// proof.ts — the HardState Proof (`.hardstate.json`): everything needed to check one event (or one citizen stamp)
// offline, against Bitcoin only. Leaves and roots are domain-separated by a one-byte kind so an event hash can never
// be passed off as a stamp or a batch root, and vice versa.

import { concat, hex, type Bytes } from "./bytes.ts";
import type { Network } from "./btc.ts";
import type { SignedEvent } from "./event.ts";
import type { CheckpointInclusion } from "./layered.ts";
import { leafHash, rootFromPath, rootFromSides } from "./merkle.ts";

export const LEAF_KIND = { event: 0x01, stamp: 0x02, batch: 0x03, index: 0x04, gap: 0x05, log: 0x06, checkpoint: 0x07 } as const;
export type LeafKind = keyof typeof LEAF_KIND;

/** The leaf hash of a 32-byte item of `kind` in a batch tree (event / stamp) or in a daily anchor tree (batch root). */
export const leafOf = (kind: LeafKind, item: Bytes) => leafHash(concat(new Uint8Array([LEAF_KIND[kind]]), item));

/** A step of a sided path: the sibling hash (hex) and the side it sits on. */
export interface SidedStep { s: "L" | "R"; h: string }

export interface InclusionProof {
  /** Root of the tree, hex. */
  root: string;
  /** Sibling hashes bottom-up with their sides. Proofs issued before sided paths carry plain hex hashes plus `index`
   * and `size` (RFC 9162 audit paths); verifiers still read those. */
  path: SidedStep[] | string[];
  /** Earlier proofs only. */
  index?: number;
  /** Earlier proofs only. */
  size?: number;
}

/** The root an inclusion proof leads to from `leaf`: a sided path, or an earlier RFC 9162 audit path. */
export async function proofRoot(leaf: Bytes, p: InclusionProof): Promise<Bytes> {
  if (p.index !== undefined || p.size !== undefined) {
    if (p.index === undefined || p.size === undefined || p.path.some((x) => typeof x !== "string")) throw new Error("malformed inclusion proof");
    return rootFromPath(leaf, p.index, p.size, (p.path as string[]).map(hex.decode));
  }
  if (p.path.some((x) => typeof x !== "object" || x === null)) throw new Error("malformed inclusion proof");
  return rootFromSides(leaf, (p.path as SidedStep[]).map((x) => ({ s: x.s, h: hex.decode(x.h) })));
}

/** Hex form of a sided path, as proofs carry it. */
export const sidesHex = (path: { s: "L" | "R"; h: Bytes }[]): SidedStep[] => path.map((x) => ({ s: x.s, h: hex.encode(x.h) }));

export interface HardStateProof {
  hardstate: "proof";
  hss: 1;
  subject:
    | { kind: "event"; signed: SignedEvent; hash: string }
    | { kind: "stamp"; digest: string };
  /** issuer.create and the key.add events that establish the signer (events only). */
  authority?: SignedEvent[];
  /** On the layered log (L1–L3): the record's place in a witnessed checkpoint of its institution's log, and that
   * checkpoint's leaf in a batch. It replaces `batch`; `ots` and `anchor` are then those of the checkpoint's batch. */
  checkpoint?: CheckpointInclusion;
  /** Inclusion of the subject in its 10-minute batch. Missing while the event waits for the next batch. */
  batch?: InclusionProof & { id: string; closedAt: string };
  /** The batch root's OpenTimestamps proof: a complete `.ots` file, base64. */
  ots?: string;
  /** The batch root's inclusion in the daily HardState Anchor and the transaction that carries it. */
  anchor?: InclusionProof & { network: Network; txid: string };
  /** Where the issuer's full log can be fetched, to check completeness and revocations. */
  logUrl?: string;
  issuedAt: string;
}

export type ProofStatus = "queued" | "batched" | "timestamped" | "anchored";

/** How far along the pipeline a proof is: queued → batched (OTS pending) → timestamped (OTS in a block) → anchored. */
export function proofStage(p: HardStateProof, otsConfirmed: boolean): ProofStatus {
  if (p.anchor) return "anchored";
  if (p.ots && otsConfirmed) return "timestamped";
  if (p.batch || p.checkpoint) return "batched";
  return "queued";
}

export const toHex = (bs: Bytes[]) => bs.map(hex.encode);
export const fromHex = (hs: string[]) => hs.map(hex.decode);
