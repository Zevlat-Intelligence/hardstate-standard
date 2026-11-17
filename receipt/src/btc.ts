// btc.ts — reading Bitcoin through public block explorers. The verifier asks more than one (any Esplora API:
// mempool.space, blockstream.info, or your own node's) and refuses to call a proof valid if they disagree, so trusting
// HardState never means trusting a single website. Nothing here signs or spends.

import { concat, equal, hex, utf8, type Bytes } from "./bytes.ts";

export type Network = "bitcoin" | "signet";

export const EXPLORERS: Record<Network, string[]> = {
  bitcoin: ["https://mempool.space/api", "https://blockstream.info/api"],
  signet: ["https://mempool.space/signet/api"],
};

export const txUrl = (network: Network, txid: string) => `https://mempool.space${network === "signet" ? "/signet" : ""}/tx/${txid}`;
export const blockUrl = (network: Network, height: number) => `https://mempool.space${network === "signet" ? "/signet" : ""}/block/${height}`;

export interface BlockInfo { height: number; hash: string; merkleRoot: string; time: number }
export interface TxInfo { txid: string; confirmed: boolean; blockHeight?: number; blockHash?: string; blockTime?: number; opReturns: string[] }

type Fetch = typeof fetch;

async function get(f: Fetch, url: string, as: "json" | "text") {
  const res = await f(url, { signal: AbortSignal.timeout(10_000) });
  if (!res.ok) throw new Error(`${url}: HTTP ${res.status}`);
  return as === "json" ? res.json() : res.text();
}

export async function blockAt(base: string, height: number, f: Fetch = fetch): Promise<BlockInfo> {
  const hash = String(await get(f, `${base}/block-height/${height}`, "text")).trim();
  const b = (await get(f, `${base}/block/${hash}`, "json")) as { id: string; height: number; merkle_root: string; timestamp: number };
  if (b.id !== hash || b.height !== height) throw new Error(`${base}: inconsistent block data`);
  return { height, hash, merkleRoot: b.merkle_root, time: b.timestamp };
}

export async function txInfo(base: string, txid: string, f: Fetch = fetch): Promise<TxInfo> {
  const t = (await get(f, `${base}/tx/${txid}`, "json")) as {
    txid: string; vout: { scriptpubkey: string; scriptpubkey_type: string }[];
    status: { confirmed: boolean; block_height?: number; block_hash?: string; block_time?: number };
  };
  return {
    txid: t.txid, confirmed: t.status.confirmed, blockHeight: t.status.block_height, blockHash: t.status.block_hash, blockTime: t.status.block_time,
    opReturns: t.vout.filter((o) => o.scriptpubkey_type === "op_return").map((o) => o.scriptpubkey),
  };
}

/**
 * Asks every explorer and requires the ones that answer to agree. `minAgree` defaults to 2 when there are two or more
 * explorers, so a single lying or compromised explorer cannot make a proof pass.
 */
export async function consensus<T>(bases: string[], ask: (base: string) => Promise<T>, key: (t: T) => string, minAgree = Math.min(2, bases.length)) {
  const rs = await Promise.allSettled(bases.map(ask));
  const ok = rs.flatMap((r, i) => (r.status === "fulfilled" ? [{ base: bases[i], value: r.value }] : []));
  if (new Set(ok.map((o) => key(o.value))).size > 1) throw new Error(`explorers disagree: ${ok.map((o) => o.base).join(", ")}`);
  if (ok.length < minAgree) throw new Error(`only ${ok.length} of ${bases.length} explorers answered (need ${minAgree})`);
  return { value: ok[0].value, sources: ok.map((o) => o.base) };
}

// ── HardState Anchor: the OP_RETURN payload ───────────────────────────────────────────────────────────────────────

/** "HSS" ‖ version ‖ 32-byte root: 36 bytes, under every relay policy's OP_RETURN limit (Knots: 40). */
export const ANCHOR_MAGIC = utf8("HSS");
export const ANCHOR_VERSION = 1;

export const anchorPayload = (root: Bytes) => {
  if (root.length !== 32) throw new Error("anchor root must be 32 bytes");
  return concat(ANCHOR_MAGIC, new Uint8Array([ANCHOR_VERSION]), root);
};

/** OP_RETURN script: 0x6a, push of 36 bytes. */
export const anchorScript = (root: Bytes) => concat(new Uint8Array([0x6a, 36]), anchorPayload(root));

/** The root a HardState OP_RETURN script carries, or null if the script is something else. */
export function parseAnchorScript(scriptHex: string): Bytes | null {
  const s = hex.decode(scriptHex);
  if (s.length !== 38 || s[0] !== 0x6a || s[1] !== 36) return null;
  if (!equal(s.slice(2, 5), ANCHOR_MAGIC) || s[5] !== ANCHOR_VERSION) return null;
  return s.slice(6);
}
