import { test } from "node:test";
import assert from "node:assert/strict";
import {
  addOp, anchorScript, applyEvent, b64, canonicalize, checkAuthority, commitFile, deserializeDetached, deserializeTimestamp, docCommitment,
  eventHashHex, hex, inclusionPath, leafHash, leafOf, newTimestamp, parseAnchorScript, replay, reverse, rootFromPath, rootOf,
  serializeDetached, serializeTimestamp, sha256, utf8, verifyEventSignature, verifyInclusion, verifyProof, otsStatus,
  type Bytes, type HardStateProof, type Timestamp,
} from "../src/index.ts";
import { demoLog, ed25519Key } from "./helpers.ts";

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

async function confirmedTimestamp(root: Bytes, height = 900_000): Promise<{ ts: Timestamp; attested: Bytes }> {
  const ts = newTimestamp(root);
  const a = await addOp(ts, { tag: 0xf0, arg: hex.decode("00112233445566778899aabbccddeeff") });
  const b = await addOp(a, { tag: 0x08 });
  b.attestations.push({ kind: "pending", uri: "https://alice.btc.calendar.opentimestamps.org" });
  const c = await addOp(b, { tag: 0xf1, arg: hex.decode("aa".repeat(32)) });
  const d = await addOp(c, { tag: 0x08 });
  const e = await addOp(d, { tag: 0x08 });
  e.attestations.push({ kind: "bitcoin", height });
  return { ts, attested: e.msg };
}

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

// ── Events, signatures, logs ───────────────────────────────────────────────────────────────────────────────────────

test("log: a well-formed log replays; passkey and Ed25519 signatures verify", async () => {
  const { log, official } = await demoLog();
  const r = await replay(log);
  assert.equal(r.error, undefined);
  assert.equal(r.state?.head.seq, 3);
  assert.ok(r.state?.keys[official.info.id]);
  const svc = await ed25519Key("official", "Permits system");
  const ev = { ...log[3].event, actor: svc.info.id };
  await verifyEventSignature(ev, await svc.sign(ev), svc.info);
});

test("log: tampering, gaps, forks and unauthorized signers are caught", async () => {
  const { log, official } = await demoLog();

  const edited = structuredClone(log);
  edited[3].event.public.result = "fail";
  assert.match((await replay(edited)).error!.message, /challenge|signature/);

  const gap = [log[0], log[1], log[3]];
  assert.match((await replay(gap)).error!.message, /expected seq 2/);

  const reordered = [log[0], log[1], log[3], log[2]];
  assert.ok((await replay(reordered)).error);

  // An official may not add keys.
  const state = (await replay(log)).state!;
  const rogue = await ed25519Key("admin", "Rogue");
  const ev = { hss: 1 as const, issuer: "demo-city", seq: 4, prev: state.head.hash, type: "key.add", ts: new Date().toISOString(), public: { key: rogue.info as never }, docs: [], actor: official.info.id };
  await assert.rejects(applyEvent(state, { event: ev, sig: await official.sign(ev) }), /admin/);

  // A passkey assertion replayed onto another event fails the challenge check.
  const other = { ...log[3].event, public: { result: "fail" } };
  await assert.rejects(verifyEventSignature(other, log[3].sig, official.info), /challenge/);
});

test("authority chain: establishes the signer without the full log", async () => {
  const { log, official } = await demoLog();
  const k = await checkAuthority([log[0], log[1]], log[3].event);
  assert.equal(k.info.id, official.info.id);
  await assert.rejects(checkAuthority([log[0]], log[3].event), /not established/);
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

// ── End to end: proof → verifier, with a fake explorer ─────────────────────────────────────────────────────────────

async function buildProof() {
  const demo = await demoLog();
  const subject = demo.log[3];
  const hash = await eventHashHex(subject.event);
  const others = await Promise.all([1, 2, 3, 4].map((i) => leafOf("stamp", new Uint8Array(32).fill(i))));
  const leaves = [...others.slice(0, 2), await leafOf("event", hex.decode(hash)), ...others.slice(2)];
  const root = await rootOf(leaves);
  const { ts, attested } = await confirmedTimestamp(root);
  const dayLeaves = [await leafOf("batch", new Uint8Array(32).fill(9)), await leafOf("batch", root)];
  const dayRoot = await rootOf(dayLeaves);
  const txid = "ab".repeat(32);
  const blocks = { 900000: { id: "00".repeat(31) + "01", merkle_root: hex.encode(reverse(attested)), timestamp: 1_792_000_000 } };
  const fakeFetch = (async (url: string) => {
    const u = String(url);
    let m = u.match(/block-height\/(\d+)$/);
    if (m) return new Response(blocks[+m[1] as 900000]?.id ?? "", { status: blocks[+m[1] as 900000] ? 200 : 404 });
    m = u.match(/block\/([0-9a-f]{64})$/);
    if (m) return Response.json({ id: m[1], height: 900000, merkle_root: blocks[900000].merkle_root, timestamp: blocks[900000].timestamp });
    m = u.match(/tx\/([0-9a-f]{64})$/);
    if (m) return Response.json({ txid: m[1], vout: [{ scriptpubkey: hex.encode(anchorScript(dayRoot)), scriptpubkey_type: "op_return" }], status: { confirmed: true, block_height: 900010, block_hash: "cc".repeat(32), block_time: 1_792_006_000 } });
    return new Response("not found", { status: 404 });
  }) as typeof fetch;
  const proof: HardStateProof = {
    hardstate: "proof", hss: 1,
    subject: { kind: "event", signed: subject, hash },
    authority: [demo.log[0], demo.log[1]],
    batch: { id: "b-1", closedAt: "2026-10-20T10:10:00Z", root: hex.encode(root), size: leaves.length, index: 2, path: (await inclusionPath(leaves, 2)).map(hex.encode) },
    ots: b64.encode(serializeDetached(ts)),
    anchor: { network: "bitcoin", txid, root: hex.encode(dayRoot), size: 2, index: 1, path: (await inclusionPath(dayLeaves, 1)).map(hex.encode) },
    issuedAt: new Date().toISOString(),
  };
  return { proof, fakeFetch, demo };
}

test("verifier: a complete proof is valid and dated by Bitcoin", async () => {
  const { proof, fakeFetch, demo } = await buildProof();
  const v = await verifyProof(proof, { fetch: fakeFetch, log: demo.log });
  assert.equal(v.status, "valid", JSON.stringify(v.steps, null, 1));
  assert.deepEqual(v.steps.map((s) => s.state), ["pass", "pass", "pass", "pass", "pass", "pass"]);
  assert.equal(v.provenBefore, 1_792_000_000);
});

test("verifier attack (a): editing the record in the database breaks it", async () => {
  const { proof, fakeFetch } = await buildProof();
  const p = structuredClone(proof);
  if (p.subject.kind === "event") p.subject.signed.event.public.result = "fail";
  const v = await verifyProof(p, { fetch: fakeFetch });
  assert.equal(v.status, "invalid");
  assert.equal(v.steps.find((s) => s.id === "integrity")?.state, "fail");
});

test("verifier attack (b): deleting an earlier record from the log is detected", async () => {
  const { proof, fakeFetch, demo } = await buildProof();
  const v = await verifyProof(proof, { fetch: fakeFetch, log: [demo.log[0], demo.log[1], demo.log[3]] });
  assert.equal(v.status, "invalid");
  assert.equal(v.steps.find((s) => s.id === "log")?.state, "fail");
});

test("verifier attack (c): a swapped document does not match", async () => {
  const { proof, fakeFetch } = await buildProof();
  const v = await verifyProof(proof, { fetch: fakeFetch, document: { file: utf8("forged report"), salt: new Uint8Array(32) } });
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
  const v = await verifyProof(noAnchor, { fetch: liar });
  assert.equal(v.steps.find((s) => s.id === "ots")?.state, "fail");

  const pending = { ...proof, ots: undefined, anchor: undefined };
  assert.equal((await verifyProof(pending, { fetch: fakeFetch })).status, "pending");
});

test("rootFromPath rejects malformed paths", async () => {
  const l = await leafHash(utf8("x"));
  await assert.rejects(rootFromPath(l, 0, 1, [l]), /too long/);
  await assert.rejects(rootFromPath(l, 0, 2, []), /too short/);
});
