// receipt.test.ts — the HardState Receipt format and its verifier: JCS, Merkle, OpenTimestamps, document commitments,
// the anchor script and proofs checked against (fake) Bitcoin explorers. No authority rules involved.

import { test } from "node:test";
import assert from "node:assert/strict";
import {
  anchorScript, canonicalize, commitFile, deserializeDetached, deserializeTimestamp, docCommitment, hex,
  inclusionPath, leafHash, otsStatus, parseAnchorScript, rootFromPath, rootOf, serializeDetached,
  serializeTimestamp, sha256, utf8, verifyInclusion, verifyReceipt,
} from "../src/index.ts";
import { buildProof, confirmedTimestamp } from "./helpers.ts";

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

test("rootFromPath rejects malformed paths", async () => {
  const l = await leafHash(utf8("x"));
  await assert.rejects(rootFromPath(l, 0, 1, [l]), /too long/);
  await assert.rejects(rootFromPath(l, 0, 2, []), /too short/);
});
