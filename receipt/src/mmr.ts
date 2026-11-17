// mmr.ts — an institution's log as a Merkle Mountain Range (MMR): an append-only forest of perfect trees over the
// log's entries in seq order. Leaves are leafOf("log", event_hash) (kind byte 0x06), so a log leaf can never pass as a
// batch leaf. The forest is built by position, never by time.
//
// The root bags the peaks from right to left. That makes it exactly the RFC 9162 Merkle Tree Hash over the same
// leaves, so an inclusion proof is an ordinary sided path (merkle.ts) that names no position and no size. A
// consistency proof between sizes m ≤ n shows the log of size n extends the log of size m unchanged: the old peaks,
// plus the perfect subtrees that cover entries m … n-1.

import { equal, hex, sha256, type Bytes } from "./bytes.ts";
import { nodeHash, rootFromSides, type Sided } from "./merkle.ts";
import { leafOf } from "./proof.ts";

/** Where the forest's nodes live: level 0 holds the leaves; node (l, i) covers leaves i·2^l … (i+1)·2^l − 1. */
export interface MmrStore {
  get(level: number, index: number): Bytes | undefined;
  set(level: number, index: number, hash: Bytes): void;
}

/** An in-memory store (tests, browsers, rebuilding from a log). */
export class MemoryMmr implements MmrStore {
  levels: Bytes[][] = [];
  get(l: number, i: number) { return this.levels[l]?.[i]; }
  set(l: number, i: number, h: Bytes) { (this.levels[l] ??= [])[i] = h; }
}

/** The log leaf for an entry. */
export const logLeaf = (eventHash: Bytes) => leafOf("log", eventHash);

const need = (s: MmrStore, l: number, i: number) => {
  const h = s.get(l, i);
  if (!h) throw new Error(`MMR node (${l}, ${i}) is missing`);
  return h;
};

/** Appends the leaf at position n (the forest had n leaves) and every parent it completes. */
export async function mmrAppend(s: MmrStore, n: number, leaf: Bytes): Promise<void> {
  s.set(0, n, leaf);
  for (let l = 0, i = n; i & 1; l++, i >>= 1) s.set(l + 1, i >> 1, await nodeHash(need(s, l, i - 1), need(s, l, i)));
}

/** The peaks of a forest of n leaves, highest first: one perfect tree per set bit of n. */
export function mmrPeaks(n: number): { level: number; index: number; start: number }[] {
  const out: { level: number; index: number; start: number }[] = [];
  let start = 0;
  for (let l = 31; l >= 0; l--) {
    const size = 2 ** l;
    if (Math.floor(n / size) % 2 === 1) { out.push({ level: l, index: start / size, start }); start += size; }
  }
  return out;
}

/** Bags peak hashes (highest first) from the right: the RFC 9162 root of the same leaves. Empty: sha256(""). */
export async function bagPeaks(peaks: Bytes[]): Promise<Bytes> {
  if (!peaks.length) return sha256(new Uint8Array());
  let acc = peaks[peaks.length - 1];
  for (let k = peaks.length - 2; k >= 0; k--) acc = await nodeHash(peaks[k], acc);
  return acc;
}

export async function mmrRoot(s: MmrStore, n: number): Promise<Bytes> {
  return bagPeaks(mmrPeaks(n).map((p) => need(s, p.level, p.index)));
}

/** The inclusion proof of leaf i in a forest of n leaves: a sided path from the leaf to the root. */
export async function mmrInclusion(s: MmrStore, n: number, i: number): Promise<Sided[]> {
  if (i < 0 || i >= n) throw new Error("leaf out of range");
  const peaks = mmrPeaks(n);
  const k = peaks.findIndex((p) => i >= p.start && i < p.start + 2 ** p.level);
  const path: Sided[] = [];
  for (let l = 0, j = i; l < peaks[k].level; l++, j >>= 1) path.push({ s: j & 1 ? "L" : "R", h: need(s, l, j ^ 1) });
  if (k < peaks.length - 1) path.push({ s: "R", h: await bagPeaks(peaks.slice(k + 1).map((p) => need(s, p.level, p.index))) });
  for (let q = k - 1; q >= 0; q--) path.push({ s: "L", h: need(s, peaks[q].level, peaks[q].index) });
  return path;
}

/** Checks that `eventHash` is in the log whose MMR root is `root`. */
export async function verifyMmrInclusion(eventHash: Bytes, path: Sided[], root: Bytes): Promise<boolean> {
  try { return equal(await rootFromSides(await logLeaf(eventHash), path), root); } catch { return false; }
}

/** The perfect subtrees that cover positions m … n-1, in order: at each position the largest aligned block that fits. */
export function coverBlocks(m: number, n: number): { level: number; index: number }[] {
  const out: { level: number; index: number }[] = [];
  for (let p = m; p < n;) {
    let l = 0;
    while (p % 2 ** (l + 1) === 0 && p + 2 ** (l + 1) <= n) l++;
    out.push({ level: l, index: p / 2 ** l });
    p += 2 ** l;
  }
  return out;
}

/** What proves the log of size n extends the log of size m: the old peaks and the blocks covering m … n-1 (hex). */
export interface ConsistencyProof { from: number; to: number; peaks: string[]; blocks: string[] }

export async function mmrConsistency(s: MmrStore, m: number, n: number): Promise<ConsistencyProof> {
  if (m < 0 || m > n) throw new Error("consistency needs 0 ≤ from ≤ to");
  return {
    from: m, to: n,
    peaks: mmrPeaks(m).map((p) => hex.encode(need(s, p.level, p.index))),
    blocks: coverBlocks(m, n).map((b) => hex.encode(need(s, b.level, b.index))),
  };
}

/** Checks a consistency proof: the old peaks bag to `oldRoot`, and appending the blocks to them yields `newRoot`. */
export async function verifyConsistency(p: ConsistencyProof, oldRoot: Bytes, newRoot: Bytes): Promise<boolean> {
  try {
    const old = mmrPeaks(p.from), blocks = coverBlocks(p.from, p.to);
    if (p.peaks.length !== old.length || p.blocks.length !== blocks.length) return false;
    const peaks = p.peaks.map((h) => hex.decode(h));
    if (!equal(await bagPeaks(peaks), oldRoot)) return false;
    // Appending an aligned block is binary addition: merge while the two last trees have the same height.
    const forest = peaks.map((h, k) => ({ level: old[k].level, h }));
    for (let k = 0; k < blocks.length; k++) {
      forest.push({ level: blocks[k].level, h: hex.decode(p.blocks[k]) });
      while (forest.length > 1 && forest[forest.length - 1].level === forest[forest.length - 2].level) {
        const r = forest.pop()!, l = forest.pop()!;
        forest.push({ level: l.level + 1, h: await nodeHash(l.h, r.h) });
      }
    }
    return equal(await bagPeaks(forest.map((t) => t.h)), newRoot);
  } catch { return false; }
}
