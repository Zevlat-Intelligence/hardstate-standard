// witness.test.ts — L2: institutions witness each other's checkpoints; equivocation is caught with signatures.

import { test } from "node:test";
import assert from "node:assert/strict";
import { b64url, checkpointHash, hex, logLeaf, MemoryMmr, mmrAppend, mmrConsistency, mmrRoot, sha256, utf8, verifyCheckpoints, type Checkpoint, type SignedCheckpoint } from "../src/index.ts";
import { conflicting, selectWitnesses, verifyEquivocation, verifyWitnessed, witnessHash, type Cosignature, type Equivocation, type WitnessKey } from "../src/index.ts";
import { ed25519Key, type TestKey } from "./helpers.ts";

async function log(n: number, salt = "") {
  const s = new MemoryMmr();
  const hashes: string[] = [];
  for (let i = 0; i < n; i++) {
    const h = await sha256(utf8(`entry ${i}${salt}`));
    hashes.push(hex.encode(h));
    await mmrAppend(s, i, await logLeaf(h));
  }
  return { s, hashes };
}

async function checkpointOf(issuer: string, n: number, operator: TestKey, salt = ""): Promise<SignedCheckpoint> {
  const { s, hashes } = await log(n, salt);
  const checkpoint: Checkpoint = { hardstate: "checkpoint", v: 1, issuer, size: n, root: hex.encode(await mmrRoot(s, n)), head: { seq: n - 1, hash: hashes[n - 1] }, ts: "2026-11-17T20:00:00Z", signer: operator.info.id };
  return { checkpoint, sigs: [{ key: operator.info.id, sig: await operator.signHash(await checkpointHash(checkpoint)) }] };
}

const cosign = async (c: Checkpoint, witness: string, k: TestKey): Promise<Cosignature> => ({ witness, key: k.info.id, sig: await k.signHash(await witnessHash(c)), ts: "2026-11-17T20:01:00Z" });

test("witness selection: deterministic from the block hash, never the issuer itself, changes with the block", async () => {
  const peers = ["valle", "valle-norte", "valle-sur", "esperanza", "puerto"];
  const a = await selectWitnesses("00".repeat(32), "valle", peers, 2);
  assert.equal(a.length, 2);
  assert.ok(!a.includes("valle"));
  assert.deepEqual(await selectWitnesses("00".repeat(32), "valle", [...peers].reverse(), 2), a, "order of candidates does not matter");
  const picks = new Set<string>();
  for (let i = 0; i < 16; i++) picks.add((await selectWitnesses(i.toString(16).padStart(64, "0"), "valle", peers, 2)).join(","));
  assert.ok(picks.size > 1, "another block chooses other witnesses");
  assert.deepEqual(await selectWitnesses("ab".repeat(32), "valle", ["valle"], 3), []);
});

test("witnessed: k distinct institutions with known keys; a forged, unknown, unselected or self cosignature does not count", async () => {
  const op = await ed25519Key("system", "Operator");
  const norte = await ed25519Key("system", "Witness"), sur = await ed25519Key("system", "Witness"), self = await ed25519Key("system", "Witness");
  const keys: WitnessKey[] = [{ issuer: "valle-norte", info: norte.info }, { issuer: "valle-sur", info: sur.info }, { issuer: "valle", info: self.info }];
  const { checkpoint: c } = await checkpointOf("valle", 9, op);
  const good = [await cosign(c, "valle-norte", norte), await cosign(c, "valle-sur", sur)];
  assert.deepEqual((await verifyWitnessed(c, good, keys, 2)).ok, true);
  // The same institution twice counts once.
  assert.equal((await verifyWitnessed(c, [good[0], { ...good[0] }], keys, 2)).ok, false);
  // A cosignature over another root does not verify.
  const other = await cosign({ ...c, root: "ff".repeat(32) }, "valle-sur", sur);
  const r = await verifyWitnessed(c, [good[0], other], keys, 2);
  assert.equal(r.ok, false);
  assert.equal(r.rejected.length, 1);
  // Unknown key, a key claimed for another institution, the issuer witnessing itself, or not selected by the block.
  const stranger = await ed25519Key("system", "Witness");
  assert.equal((await verifyWitnessed(c, [await cosign(c, "valle-norte", stranger)], keys, 1)).ok, false);
  assert.equal((await verifyWitnessed(c, [{ ...good[1], witness: "valle-norte" }], keys, 1)).ok, false);
  assert.equal((await verifyWitnessed(c, [await cosign(c, "valle", self)], keys, 1)).ok, false);
  assert.equal((await verifyWitnessed(c, good, keys, 2, ["valle-norte"])).ok, false);
});

test("a witness signs only after checking that the new checkpoint extends the one it signed before", async () => {
  const op = await ed25519Key("system", "Operator");
  const { s } = await log(20);
  const a = (await checkpointOf("valle", 12, op)).checkpoint, b = (await checkpointOf("valle", 20, op)).checkpoint;
  assert.ok(await verifyCheckpoints(a, b, await mmrConsistency(s, 12, 20)));
  // A rewritten past (another entry inside the first 12) is not an extension.
  const forked = (await checkpointOf("valle", 20, op, "x")).checkpoint;
  assert.equal(await verifyCheckpoints(a, forked, await mmrConsistency((await log(20, "x")).s, 12, 20)), false);
});

test("equivocation: two signed checkpoints of the same size that disagree prove a fork, with the operator's or a witness's key", async () => {
  const op = await ed25519Key("system", "Operator");
  const a = await checkpointOf("valle", 10, op), b = await checkpointOf("valle", 10, op, "rewritten");
  assert.ok(conflicting(a.checkpoint, b.checkpoint));
  const e: Equivocation = { hardstate: "equivocation", v: 1, issuer: "valle", size: 10, a, b, key: op.info.id };
  assert.deepEqual(await verifyEquivocation(e, op.info), { root: true, head: true });
  // A witness that signed both histories is caught too: its cosignatures ride in `sigs` as { key, sig }.
  const w = await ed25519Key("system", "Witness");
  const wa = { ...a, sigs: [{ key: w.info.id, sig: (await cosign(a.checkpoint, "valle-norte", w)).sig }] };
  const wb = { ...b, sigs: [{ key: w.info.id, sig: (await cosign(b.checkpoint, "valle-norte", w)).sig }] };
  assert.deepEqual(await verifyEquivocation({ ...e, a: wa, b: wb, key: w.info.id }, w.info), { root: true, head: true });
  // Agreeing checkpoints, another size, or a forged signature are not evidence.
  await assert.rejects(verifyEquivocation({ ...e, b: a }, op.info), /no fork/);
  await assert.rejects(verifyEquivocation({ ...e, size: 11 }, op.info), /same size/);
  const forged = { ...b, sigs: [{ key: op.info.id, sig: { kind: "ed25519" as const, signature: b64url.encode(new Uint8Array(64)) } }] };
  await assert.rejects(verifyEquivocation({ ...e, b: forged }, op.info));
});
