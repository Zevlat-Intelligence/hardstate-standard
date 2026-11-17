// layered.test.ts — L3: a witnessed checkpoint is one batch leaf; a record's receipt goes record → log checkpoint (MMR)
// → checkpoint leaf → batch → Bitcoin, and verifies like any receipt.

import { test } from "node:test";
import assert from "node:assert/strict";
import {
  b64, checkpointHash, checkpointLeafData, cosigSetHash, eventHashHex, hex, leafOf, logLeaf, MemoryMmr, mmrAppend, mmrInclusion,
  mmrRoot, reverse, rootOf, serializeDetached, sidedPath, sidesHex, verifyReceipt, witnessHash,
  type Checkpoint, type CheckpointInclusion, type Cosignature, type HardStateProof, type SignedCheckpoint, type WitnessKey,
} from "../src/index.ts";
import { confirmedTimestamp, demoLog, ed25519Key, type TestKey } from "./helpers.ts";

async function layeredProof() {
  const demo = await demoLog();
  const operator = await ed25519Key("system", "Operator");
  const w1 = await ed25519Key("system", "Witness A"), w2 = await ed25519Key("system", "Witness B");
  const hashes = await Promise.all(demo.log.map((s) => eventHashHex(s.event)));
  const store = new MemoryMmr();
  for (let i = 0; i < hashes.length; i++) await mmrAppend(store, i, await logLeaf(hex.decode(hashes[i])));
  const n = hashes.length;
  const checkpoint: Checkpoint = { hardstate: "checkpoint", v: 1, issuer: "demo-city", size: n, root: hex.encode(await mmrRoot(store, n)), head: { seq: n - 1, hash: hashes[n - 1] }, ts: "2026-11-17T20:00:00Z", signer: operator.info.id };
  const signed: SignedCheckpoint = { checkpoint, sigs: [{ key: operator.info.id, sig: await operator.signHash(await checkpointHash(checkpoint)) }] };
  const cosign = async (witness: string, k: TestKey): Promise<Cosignature> => ({ witness, key: k.info.id, sig: await k.signHash(await witnessHash(checkpoint)), ts: "2026-11-17T20:01:00Z" });
  const cosigs = [await cosign("city-b", w2), await cosign("city-a", w1)];
  const witnessKeys: WitnessKey[] = [{ issuer: "city-a", info: w1.info }, { issuer: "city-b", info: w2.info }];
  // The batch: a stamp, the checkpoint's leaf, an event of another institution.
  const leaves = [await leafOf("stamp", new Uint8Array(32).fill(1)), await leafOf("checkpoint", await checkpointLeafData(signed, cosigs)), await leafOf("event", new Uint8Array(32).fill(3))];
  const root = await rootOf(leaves);
  const { ts, attested } = await confirmedTimestamp(root);
  const block = { id: "00".repeat(31) + "01", merkle_root: hex.encode(reverse(attested)), timestamp: 1_792_000_000 };
  const fakeFetch = (async (url: string) => {
    const u = String(url);
    if (/block-height\/\d+$/.test(u)) return new Response(block.id);
    const m = u.match(/block\/([0-9a-f]{64})$/);
    if (m) return Response.json({ id: m[1], height: 900000, merkle_root: block.merkle_root, timestamp: block.timestamp });
    return new Response("not found", { status: 404 });
  }) as typeof fetch;
  const subject = demo.log[3];
  const ci: CheckpointInclusion = {
    signed, cosigs, witnessKeys, witnesses: { height: 900000, blockHash: "aa".repeat(32), selected: ["city-a", "city-b"] },
    path: sidesHex(await mmrInclusion(store, n, 3)),
    batch: { id: "b-7", closedAt: "2026-11-17T20:10:00Z", root: hex.encode(root), path: sidesHex(await sidedPath(leaves, 1)) },
  };
  const proof: HardStateProof = {
    hardstate: "proof", hss: 1, subject: { kind: "event", signed: subject, hash: hashes[3] }, authority: [demo.log[0], demo.log[1]],
    checkpoint: ci, ots: b64.encode(serializeDetached(ts)), issuedAt: new Date().toISOString(),
  };
  return { proof, fakeFetch, operator };
}

test("layered receipt: record → witnessed checkpoint → batch → Bitcoin verifies, naming the witnesses", async () => {
  const { proof, fakeFetch, operator } = await layeredProof();
  const v = await verifyReceipt(proof, { fetch: fakeFetch, operatorKey: operator.info, witnessK: 2 });
  assert.equal(v.status, "valid", JSON.stringify(v.steps, null, 1));
  const b = v.steps.find((s) => s.id === "batch")!;
  assert.equal(b.detail, "The record is in checkpoint #3 of the institution's log, witnessed by 2 other institutions (city-a, city-b), which is in batch b-7.");
  assert.equal(b.facts?.operatorChecked, true);
  assert.equal(v.provenBefore, 1_792_000_000);
});

test("layered receipt: the cosignature set is order-free but exact; tampering with any layer fails", async () => {
  const { proof, fakeFetch, operator } = await layeredProof();
  const ci = proof.checkpoint!;
  assert.deepEqual(await cosigSetHash(ci.cosigs), await cosigSetHash([...ci.cosigs].reverse()));
  const bad = async (p: HardStateProof, o = {}) => (await verifyReceipt(p, { fetch: fakeFetch, ...o })).steps.find((s) => s.id === "batch")!.state;
  // A cosignature dropped after batching: the leaf no longer matches.
  const dropped = structuredClone(proof); dropped.checkpoint!.cosigs.pop(); dropped.checkpoint!.witnessKeys = undefined;
  assert.equal(await bad(dropped), "fail");
  // Another record claimed under the same path.
  const other = structuredClone(proof); other.checkpoint!.path[0] = { ...other.checkpoint!.path[0], s: other.checkpoint!.path[0].s === "L" ? "R" : "L" };
  assert.equal(await bad(other), "fail");
  // The checkpoint rewritten (another root): neither the record nor the leaf match.
  const rewritten = structuredClone(proof); rewritten.checkpoint!.signed.checkpoint.root = "11".repeat(32);
  assert.equal(await bad(rewritten), "fail");
  // A checkpoint of another institution's log.
  const foreign = structuredClone(proof); foreign.checkpoint!.signed.checkpoint.issuer = "elsewhere";
  assert.equal(await bad(foreign), "fail");
  // A forged operator signature, when the verifier holds the operator's key.
  // (a real signature, but a witness's over another hash).
  const forged = structuredClone(proof); forged.checkpoint!.signed.sigs[0].sig = forged.checkpoint!.cosigs[0].sig;
  assert.equal(await bad(forged, { operatorKey: operator.info }), "fail");
  // A witness the block did not choose does not count.
  const unchosen = structuredClone(proof); unchosen.checkpoint!.witnesses!.selected = ["city-a"];
  assert.equal(await bad(unchosen), "fail");
});
