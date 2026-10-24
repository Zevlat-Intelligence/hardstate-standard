// merkle.ts — the batch tree. RFC 6962 / RFC 9162 Merkle Tree Hash: leaves hashed as sha256(0x00 ‖ leaf), nodes as
// sha256(0x01 ‖ left ‖ right), the split at the largest power of two below n. The prefixes keep a leaf from ever
// passing as a node (second-preimage), and the shape is the one Certificate Transparency logs use, so its inclusion
// proofs are well understood.

import { concat, equal, sha256, type Bytes } from "./bytes.ts";

export const leafHash = (leaf: Bytes) => sha256(concat(new Uint8Array([0]), leaf));
export const nodeHash = (l: Bytes, r: Bytes) => sha256(concat(new Uint8Array([1]), l, r));

/** Largest power of two strictly below n (n ≥ 2). */
const split = (n: number) => { let k = 1; while (k * 2 < n) k *= 2; return k; };

/** The root over leaf hashes (already passed through leafHash). An empty tree's root is sha256(""). */
export async function rootOf(leaves: Bytes[]): Promise<Bytes> {
  if (leaves.length === 0) return sha256(new Uint8Array());
  if (leaves.length === 1) return leaves[0];
  const k = split(leaves.length);
  return nodeHash(await rootOf(leaves.slice(0, k)), await rootOf(leaves.slice(k)));
}

/** RFC 9162 §2.1.3.1 inclusion path for leaf `index`, bottom-up. */
export async function inclusionPath(leaves: Bytes[], index: number): Promise<Bytes[]> {
  if (index < 0 || index >= leaves.length) throw new Error("leaf index out of range");
  if (leaves.length === 1) return [];
  const k = split(leaves.length);
  return index < k
    ? [...(await inclusionPath(leaves.slice(0, k), index)), await rootOf(leaves.slice(k))]
    : [...(await inclusionPath(leaves.slice(k), index - k)), await rootOf(leaves.slice(0, k))];
}

/** RFC 9162 §2.1.3.2: recompute the root from a leaf hash, its index, the tree size and the path. */
export async function rootFromPath(leaf: Bytes, index: number, size: number, path: Bytes[]): Promise<Bytes> {
  if (index < 0 || index >= size) throw new Error("leaf index out of range");
  let fn = index, sn = size - 1, r = leaf;
  for (const p of path) {
    if (sn === 0) throw new Error("inclusion path too long");
    if (fn & 1 || fn === sn) {
      r = await nodeHash(p, r);
      if (!(fn & 1)) while (fn !== 0 && !(fn & 1)) { fn >>= 1; sn >>= 1; }
    } else {
      r = await nodeHash(r, p);
    }
    fn >>= 1; sn >>= 1;
  }
  if (sn !== 0) throw new Error("inclusion path too short");
  return r;
}

export async function verifyInclusion(leaf: Bytes, index: number, size: number, path: Bytes[], root: Bytes): Promise<boolean> {
  try { return equal(await rootFromPath(leaf, index, size, path), root); } catch { return false; }
}
