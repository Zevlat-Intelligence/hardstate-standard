// proof.ts — the HardState Proof (`.hardstate.json`): everything needed to check one event (or one citizen stamp)
// offline, against Bitcoin only. Leaves and roots are domain-separated by a one-byte kind so an event hash can never
// be passed off as a stamp or a batch root, and vice versa.

import { concat, hex, type Bytes } from "./bytes.ts";
import type { Network } from "./btc.ts";
import type { SignedEvent } from "./event.ts";
import { leafHash } from "./merkle.ts";

export const LEAF_KIND = { event: 0x01, stamp: 0x02, batch: 0x03 } as const;
export type LeafKind = keyof typeof LEAF_KIND;

/** The leaf hash of a 32-byte item of `kind` in a batch tree (event / stamp) or in a daily anchor tree (batch root). */
export const leafOf = (kind: LeafKind, item: Bytes) => leafHash(concat(new Uint8Array([LEAF_KIND[kind]]), item));

export interface InclusionProof {
  /** Root of the tree, hex. */
  root: string;
  size: number;
  index: number;
  /** Sibling hashes bottom-up (RFC 9162), hex. */
  path: string[];
}

export interface HardStateProof {
  hardstate: "proof";
  hss: 1;
  subject:
    | { kind: "event"; signed: SignedEvent; hash: string }
    | { kind: "stamp"; digest: string };
  /** issuer.create and the key.add events that establish the signer (events only). */
  authority?: SignedEvent[];
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
  if (p.batch) return "batched";
  return "queued";
}

export const toHex = (bs: Bytes[]) => bs.map(hex.encode);
export const fromHex = (hs: string[]) => hs.map(hex.decode);
