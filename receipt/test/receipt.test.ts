// receipt.test.ts — the HardState Receipt format and its verifier: JCS, Merkle, OpenTimestamps, document commitments,
// the anchor script and proofs checked against (fake) Bitcoin explorers. No authority rules involved.

import { test } from "node:test";
import assert from "node:assert/strict";
import {
  anchorScript, canonicalize, commitFile, deserializeDetached, deserializeTimestamp, docCommitment, hex,
  inclusionPath, leafHash, otsStatus, parseAnchorScript, rootFromPath, rootFromSides, rootOf, serializeDetached, sidedPath,
  eventHash, serializeTimestamp, sha256, streamDigest, utf8, verifyAbsence, verifyInclusion, verifyReceipt, verifyStream,
} from "../src/index.ts";
import { buildAbsence, buildProof, confirmedTimestamp, demoLog, ed25519Key } from "./helpers.ts";

// ── JCS ────────────────────────────────────────────────────────────────────────────────────────────────────────────

test("JCS: RFC 8785 §3.2.2 sample", () => {
  const input = JSON.parse('{"numbers":[333333333.33333329,1E30,4.50,2e-3,0.000000000000000000000000001],"string":"\\u20ac$\\u000F\\u000aA\'\\u0042\\u0022\\u005c\\\\\\"\\/","literals":[null,true,false]}');
  assert.equal(canonicalize(input), '{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],"string":"€$\\u000f\\nA\'B\\"\\\\\\\\\\"/"}');
});

test("JCS: keys sort by UTF-16 code units, undefined dropped, non-finite refused", () => {
  assert.equal(canonicalize({ b: 1, a: [1, { d: undefined, c: "x" }], "€": 1, "\r": 2 }), '{"\\r":2,"a":[1,{"c":"x"}],"b":1,"€":1}');
  assert.throws(() => canonicalize({ x: NaN }));
});

// ── Merkle ─────────────────────────────────────────────────────────────────────────────────────────────────────────

const CT_LEAVES = ["", "00", "10", "2021", "3031", "40414243", "5051525354555657", "606162636465666768696a6b6c6d6e6f"];

test("Merkle: RFC 6962 / Certificate Transparency test vector", async () => {
  const leaves = await Promise.all(CT_LEAVES.map((l) => leafHash(hex.decode(l))));
  assert.equal(hex.encode(await rootOf(leaves)), "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328");
  assert.equal(hex.encode(await rootOf(leaves.slice(0, 1))), "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d");
  assert.equal(hex.encode(await rootOf(leaves.slice(0, 3))), "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77");
});

test("Merkle: every inclusion path verifies, wrong index / leaf / size does not", async () => {
  for (let n = 1; n <= 23; n++) {
    const leaves = await Promise.all(Array.from({ length: n }, (_, i) => leafHash(utf8(`leaf ${i}`))));
    const root = await rootOf(leaves);
    for (let i = 0; i < n; i++) {
      const path = await inclusionPath(leaves, i);
      assert.ok(await verifyInclusion(leaves[i], i, n, path, root), `n=${n} i=${i}`);
      if (n > 1) {
        assert.ok(!(await verifyInclusion(leaves[(i + 1) % n], i, n, path, root)), `wrong leaf n=${n} i=${i}`);
        assert.ok(!(await verifyInclusion(leaves[i], (i + 1) % n, n, path, root)) || (i + 1) % n === i, `wrong index n=${n} i=${i}`);
      }
    }
  }
});

test("Merkle: sided paths verify for every leaf of every size, with no index or size; a flipped side or sibling fails", async () => {
  for (let n = 1; n <= 23; n++) {
    const leaves = await Promise.all(Array.from({ length: n }, (_, i) => leafHash(utf8(`leaf ${i}`))));
    const root = await rootOf(leaves);
    for (let i = 0; i < n; i++) {
      const path = await sidedPath(leaves, i);
      assert.deepEqual(await rootFromSides(leaves[i], path), root, `n=${n} i=${i}`);
      assert.equal(path.length, (await inclusionPath(leaves, i)).length);
      if (path.length) {
        const flipped = path.map((p, j) => (j === 0 ? { ...p, s: p.s === "L" ? "R" as const : "L" as const } : p));
        assert.notDeepEqual(await rootFromSides(leaves[i], flipped), root, `flipped n=${n} i=${i}`);
        if (n > 1) assert.notDeepEqual(await rootFromSides(leaves[(i + 1) % n], path), root, `wrong leaf n=${n} i=${i}`);
      }
    }
  }
  await assert.rejects(rootFromSides(new Uint8Array(32), [{ s: "X" as "L", h: new Uint8Array(32) }]), /side/);
});

// ── OpenTimestamps ─────────────────────────────────────────────────────────────────────────────────────────────────

test("OTS: detached file round-trips byte for byte and keeps the tree", async () => {
  const root = await sha256(utf8("batch"));
  const { ts } = await confirmedTimestamp(root);
  const file = serializeDetached(ts);
  assert.equal(hex.encode(file.slice(0, 31)), "004f70656e54696d657374616d7073000050726f6f6600bf89e2e884e89294");
  const back = await deserializeDetached(file);
  assert.deepEqual(serializeDetached(back), file);
  assert.equal(otsStatus(back), "confirmed");
  const inner = serializeTimestamp(ts);
  assert.deepEqual(serializeTimestamp(await deserializeTimestamp(inner, root)), inner);
  await assert.rejects(deserializeDetached(file.slice(0, file.length - 1)));
});

test("OTS: parses a timestamp produced by the reference client", async () => {
  // A calendar answer shape: append(nonce16) sha256 → pending attestation (from python-opentimestamps' own tests).
  const msg = hex.decode("ff".repeat(32));
  const bytes = hex.decode("f010" + "00".repeat(16) + "08" + "00" + "83dfe30d2ef90c8e" + "2e" + "2d" + hex.encode(utf8("https://alice.btc.calendar.opentimestamps.org")));
  const ts = await deserializeTimestamp(bytes, msg);
  assert.equal(ts.ops.length, 1);
  assert.equal(ts.ops[0].ts.ops[0].ts.attestations[0].kind, "pending");
  assert.deepEqual(serializeTimestamp(ts), bytes);
});

test("documents: salted commitments match only with the right salt", async () => {
  const file = utf8("%PDF-1.7 site plan");
  const c = await commitFile(file);
  assert.equal(hex.encode(await docCommitment(await sha256(file), hex.decode(c.salt))), c.commitment);
  assert.notEqual(hex.encode(await docCommitment(await sha256(file), new Uint8Array(32))), c.commitment);
});

test("anchor script: HSS ‖ 0x01 ‖ root, 36 bytes", async () => {
  const root = await sha256(utf8("day"));
  const s = anchorScript(root);
  assert.equal(s.length, 38);
  assert.equal(hex.encode(s.slice(0, 6)), "6a2448535301");
  assert.deepEqual(parseAnchorScript(hex.encode(s)), root);
  assert.equal(parseAnchorScript("6a0401020304"), null);
});

// ── Proofs against Bitcoin explorers ────────────────────────────────────────

test("verifier attack (a): editing the record in the database breaks it", async () => {
  const { proof, fakeFetch } = await buildProof();
  const p = structuredClone(proof);
  if (p.subject.kind === "event") p.subject.signed.event.public.result = "fail";
  const v = await verifyReceipt(p, { fetch: fakeFetch });
  assert.equal(v.status, "invalid");
  assert.equal(v.steps.find((s) => s.id === "integrity")?.state, "fail");
});

test("verifier attack (c): a swapped document does not match", async () => {
  const { proof, fakeFetch } = await buildProof();
  const v = await verifyReceipt(proof, { fetch: fakeFetch, document: { file: utf8("forged report"), salt: new Uint8Array(32) } });
  assert.equal(v.status, "invalid");
  assert.equal(v.steps.find((s) => s.id === "document")?.state, "fail");
});

test("verifier: explorers that disagree make it fail; no attestation yet keeps it pending", async () => {
  const { proof, fakeFetch } = await buildProof();
  const liar = (async (url: string) => {
    const r = await fakeFetch(url);
    if (String(url).startsWith("https://blockstream.info") && /block\/[0-9a-f]{64}$/.test(String(url))) {
      const j = await r.json();
      return Response.json({ ...j, merkle_root: "ee".repeat(32) });
    }
    return r;
  }) as typeof fetch;
  const noAnchor = { ...proof, anchor: undefined };
  const v = await verifyReceipt(noAnchor, { fetch: liar });
  assert.equal(v.steps.find((s) => s.id === "ots")?.state, "fail");

  const pending = { ...proof, ots: undefined, anchor: undefined };
  assert.equal((await verifyReceipt(pending, { fetch: fakeFetch })).status, "pending");
});

test("receipt verifier: proofs issued before sided paths (index + size) still verify", async () => {
  const { proof, fakeFetch } = await buildProof({ legacy: true });
  const v = await verifyReceipt(proof, { fetch: fakeFetch });
  assert.equal(v.status, "valid", JSON.stringify(v.steps, null, 1));
  assert.match(v.steps.find((s) => s.id === "batch")!.detail, /^Entry 3 of 5 in batch b-1\.$/);
  const fresh = await verifyReceipt((await buildProof()).proof, { fetch: fakeFetch });
  assert.equal(fresh.steps.find((s) => s.id === "batch")!.detail, "The record is in batch b-1.");
});

test("receipt verifier: a sided path with a wrong side is rejected", async () => {
  const { proof, fakeFetch } = await buildProof();
  const p = structuredClone(proof);
  const path = p.batch!.path as { s: "L" | "R"; h: string }[];
  path[0] = { ...path[0], s: path[0].s === "L" ? "R" : "L" };
  const v = await verifyReceipt(p, { fetch: fakeFetch });
  assert.equal(v.status, "invalid");
  assert.equal(v.steps.find((s) => s.id === "batch")?.state, "fail");
});

test("rootFromPath rejects malformed paths", async () => {
  const l = await leafHash(utf8("x"));
  await assert.rejects(rootFromPath(l, 0, 1, [l]), /too long/);
  await assert.rejects(rootFromPath(l, 0, 2, []), /too short/);
});

// ── Proof of Absence ─────────────────────────────────────────────────────────────────────────────────────────────

const ENTRIES: [("review" | "revoke" | "doc"), string][] = [["review", "aa".repeat(32)], ["review", "bb".repeat(32)], ["revoke", "ed25519:0011"], ["doc", "cc".repeat(32)]];

test("absence: a key inside a gap of an anchored index proves nothing of that kind existed as of the entry", async () => {
  const { proof, fakeFetch } = await buildAbsence(ENTRIES, ["review", "dd".repeat(32)]);
  const v = await verifyAbsence(proof, { fetch: fakeFetch });
  assert.equal(v.status, "valid", JSON.stringify(v.steps, null, 1));
  assert.deepEqual(v.steps.map((s) => s.id), ["absence", "batch", "ots", "anchor"]);
  assert.equal(v.steps[0].detail, "As of entry #7 of the institution's log, there was no human review of this decision.");
  assert.equal(v.provenBefore, 1_792_000_000);
});

test("absence: an empty index proves every key absent", async () => {
  const { proof, fakeFetch } = await buildAbsence([], ["revoke", "ed25519:ffee"]);
  assert.equal((await verifyAbsence(proof, { fetch: fakeFetch })).status, "valid");
});

test("absence attacks: a key that exists, a forged gap or another log entry all fail", async () => {
  const { proof, fakeFetch } = await buildAbsence(ENTRIES, ["review", "dd".repeat(32)]);
  // The key exists: no gap strictly contains it (asking about a recorded review with this gap fails).
  const present = structuredClone(proof); present.query = { kind: "review", id: "aa".repeat(32) };
  assert.equal((await verifyAbsence(present, { fetch: fakeFetch })).steps[0].state, "fail");
  // A forged, wider gap is not in the index.
  const wide = structuredClone(proof); wide.gap.lo = "00".repeat(32); wide.gap.hi = "ff".repeat(32);
  assert.equal((await verifyAbsence(wide, { fetch: fakeFetch })).status, "invalid");
  // The same index claimed for a later log entry is not the leaf the batch holds.
  const later = structuredClone(proof); later.asOf = { ...later.asOf, seq: 8 };
  assert.equal((await verifyAbsence(later, { fetch: fakeFetch })).steps.find((s) => s.id === "batch")?.state, "fail");
});

// ── Completeness of an AI system's stream ──────────────────────────────────────────────────────────────────────────

/** Two heartbeats of process "i1" around: its decision, a decision of another process "i2", an official's step and its
 * failed run. `beat` overrides what the second heartbeat says. */
async function stream(beat: (said: Record<string, unknown>) => Record<string, unknown> = (x) => x) {
  const { log, append, official } = await demoLog();
  const ai = await ed25519Key("system", "Permit pre-review (AI)");
  const sys = { system: "Pre-review", model: "m", version: "1" };
  const first = await append(ai, { type: "ai.heartbeat", public: { ...sys, instance: "i1", every: 3600, decisions: 0, runs: 0, failures: 0 }, docs: [] });
  const d = await append(ai, { type: "ai.decision", case: "BP-1", public: { ...sys, instance: "i1", outcome: "approve", oversight: "required" }, docs: [] });
  await append(ai, { type: "ai.decision", case: "BP-2", public: { ...sys, instance: "i2", outcome: "deny", oversight: "required" }, docs: [] });
  await append(official, { type: "case.review", case: "BP-1", public: {}, docs: [] });
  const r = await append(ai, { type: "ai.run", case: "BP-3", public: { ...sys, instance: "i1", steps: 2, root: "00".repeat(32), outcome: "failed", error: "timeout" }, docs: [] });
  const digest = hex.encode(await streamDigest([await eventHash(d.event), await eventHash(r.event)]));
  const second = await append(ai, { type: "ai.heartbeat", public: beat({ ...sys, instance: "i1", every: 3600, decisions: 1, runs: 1, failures: 1, digest, since: first.event.seq }) as never, docs: [] });
  return { first, second, segment: log.slice(first.event.seq + 1, second.event.seq) };
}

test("stream: the log between two heartbeats holds exactly the records the process vouched for", async () => {
  const { first, second, segment } = await stream();
  const r = await verifyStream(first, second, segment);
  assert.equal(r.state, "complete", r.detail);
  assert.deepEqual([r.facts.records, r.facts.decisions, r.facts.runs, r.facts.failures, r.facts.digest], [2, 1, 1, 1, true]);
});

test("stream: a record the process made but the log does not hold is caught by the count and by the digest", async () => {
  const counted = await stream((x) => ({ ...x, decisions: 2 }));
  const a = await verifyStream(counted.first, counted.second, counted.segment);
  assert.equal(a.state, "missing");
  assert.match(a.detail, /counts 2 decisions, but the log holds 1/);
  const forged = await stream((x) => ({ ...x, digest: "00".repeat(32) }));
  assert.equal((await verifyStream(forged.first, forged.second, forged.segment)).state, "missing");
});

test("stream: a late heartbeat is a gap; a slice that skips an entry or a beat that points elsewhere does not link", async () => {
  const late = await stream((x) => ({ ...x, every: 60 }));
  assert.equal((await verifyStream(late.first, late.second, late.segment)).state, "gap");
  const { first, second, segment } = await stream();
  assert.equal((await verifyStream(first, second, segment.filter((_, i) => i !== 1))).state, "unlinked");
  const swapped = [...segment]; [swapped[0], swapped[1]] = [swapped[1], swapped[0]];
  assert.equal((await verifyStream(first, second, swapped)).state, "unlinked");
  const elsewhere = await stream((x) => ({ ...x, since: 2 }));
  assert.equal((await verifyStream(elsewhere.first, elsewhere.second, elsewhere.segment)).state, "unlinked");
});
