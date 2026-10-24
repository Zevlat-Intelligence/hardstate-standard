import { test } from "node:test";
import assert from "node:assert/strict";
import {
  addOp, applyEvent, b64, checkAuthority, eventHashHex, hex, leafOf, newTimestamp, replay, reverse, rootOf, serializeDetached,
  typeAllowed, verifyProof, type HardStateProof, type HssEvent, type KeyInfo,
} from "../src/index.ts";
import { demoLog, ed25519Key, type TestKey } from "./helpers.ts";

const H = 3_600_000;
const iso = (ms: number) => new Date(ms).toISOString();

/** demoLog (issuer.create by admin, key.add official, two case events) plus a builder that controls ts. */
async function setup() {
  const demo = await demoLog();
  const log = [...demo.log];
  const t0 = Date.parse(log[log.length - 1].event.ts) + 60_000;
  const add = async (signer: TestKey, partial: Partial<HssEvent> & { type: string }, ts = t0 + log.length * 60_000) => {
    const event: HssEvent = { hss: 1, issuer: "demo-city", seq: log.length, prev: await eventHashHex(log[log.length - 1].event), ts: iso(ts), actor: signer.info.id, public: {}, docs: [], ...partial };
    const s = { event, sig: await signer.sign(event) };
    log.push(s);
    return s;
  };
  const session = async (label: string, scope: KeyInfo["scope"]) => {
    const k = await ed25519Key("official", label);
    const info: KeyInfo = { ...k.info, role: "session", scope };
    return { info, sign: k.sign } as TestKey;
  };
  return { ...demo, log, t0, add, session };
}

test("scope: exact types and domain wildcards", () => {
  assert.ok(typeAllowed(undefined, "case.open"));
  assert.ok(typeAllowed({ types: ["fee.paid"] }, "fee.paid"));
  assert.ok(typeAllowed({ types: ["case.*"] }, "case.inspect"));
  assert.ok(!typeAllowed({ types: ["case.*"] }, "permit.approve"));
  assert.ok(!typeAllowed({ types: ["fee.paid"] }, "fee.refund"));
});

test("sessions: an official opens one; it signs steps on their behalf, attributed to them", async () => {
  const s = await setup();
  const ses = await session8h(s);
  await s.add(s.official, { type: "session.open", public: { key: ses.info as never, device: "Inspector tablet" } });
  const step = await s.add(ses, { type: "case.inspect", case: "BP-2026-0042", public: { result: "pass" } });
  const r = await replay(s.log);
  assert.equal(r.error, undefined, r.error?.message);
  assert.equal(r.state!.keys[ses.info.id].delegatedBy, s.official.info.id);

  // A proof carries issuer.create, the official's key.add and the session.open: enough to attribute it offline.
  const auth = await checkAuthority([s.log[0], s.log[1], s.log[4]], step.event);
  assert.equal(auth.delegator?.info.id, s.official.info.id);
  const v = await verifyProof({ hardstate: "proof", hss: 1, subject: { kind: "event", signed: step, hash: await eventHashHex(step.event) }, authority: [s.log[0], s.log[1], s.log[4]], issuedAt: iso(Date.now()) });
  const sig = v.steps.find((x) => x.id === "signature")!;
  assert.equal(sig.state, "pass");
  assert.equal(sig.facts?.signer, "Ana López — Building inspector");
  assert.equal(sig.facts?.session, "Inspector tablet session");
});

async function session8h(s: Awaited<ReturnType<typeof setup>>, types?: string[]) {
  return s.session("Inspector tablet session", { expires: iso(s.t0 + 8 * H), ...(types ? { types } : {}) });
}

test("sessions: scope, expiry and the 30-day cap are enforced", async () => {
  const s = await setup();
  const ses = await session8h(s, ["case.*"]);
  await s.add(s.official, { type: "session.open", public: { key: ses.info as never } });

  // Out of scope.
  let state = (await replay(s.log)).state!;
  const permit: HssEvent = { hss: 1, issuer: "demo-city", seq: s.log.length, prev: state.head.hash, type: "permit.approve", ts: iso(s.t0 + H), public: {}, docs: [], actor: ses.info.id };
  await assert.rejects(applyEvent(state, { event: permit, sig: await ses.sign(permit) }), /may only sign case\.\*/);

  // After expiry (by the event's time), and by the operator's receive time.
  const late: HssEvent = { ...permit, type: "case.review", ts: iso(s.t0 + 9 * H) };
  await assert.rejects(applyEvent(state, { event: late, sig: await ses.sign(late) }), /expired/);
  const backdated: HssEvent = { ...permit, type: "case.review", ts: iso(s.t0 + H) };
  await assert.rejects(applyEvent(state, { event: backdated, sig: await ses.sign(backdated) }, { receivedAt: iso(s.t0 + 9 * H) }), /expired/);
  state = await applyEvent(state, { event: backdated, sig: await ses.sign(backdated) }, { receivedAt: iso(s.t0 + 2 * H) });

  // More than 30 days.
  const long = await s.session("Too long", { expires: iso(s.t0 + 31 * 24 * H) });
  const open: HssEvent = { hss: 1, issuer: "demo-city", seq: state.head.seq + 1, prev: state.head.hash, type: "session.open", ts: iso(s.t0 + 2 * H), public: { key: long.info as never }, docs: [], actor: s.official.info.id };
  await assert.rejects(applyEvent(state, { event: open, sig: await s.official.sign(open) }), /30 days/);
});

test("sessions: cannot manage keys or open more sessions; system keys need a scope", async () => {
  const s = await setup();
  const ses = await session8h(s);
  await s.add(s.official, { type: "session.open", public: { key: ses.info as never } });
  const state = (await replay(s.log)).state!;
  const other = await s.session("Other", { expires: iso(s.t0 + H) });
  const nested: HssEvent = { hss: 1, issuer: "demo-city", seq: state.head.seq + 1, prev: state.head.hash, type: "session.open", ts: iso(s.t0 + 10 * 60_000), public: { key: other.info as never }, docs: [], actor: ses.info.id };
  await assert.rejects(applyEvent(state, { event: nested, sig: await ses.sign(nested) }), /only a person/);

  const sys = await ed25519Key("official", "Payments gateway");
  const unscoped: KeyInfo = { ...sys.info, role: "system" };
  const addSys: HssEvent = { ...nested, type: "key.add", public: { key: unscoped as never }, actor: s.admin.info.id };
  await assert.rejects(applyEvent(state, { event: addSys, sig: await s.admin.sign(addSys) }), /must be scoped/);
  const viaKeyAdd: HssEvent = { ...addSys, public: { key: other.info as never } };
  await assert.rejects(applyEvent(state, { event: viaKeyAdd, sig: await s.admin.sign(viaKeyAdd) }), /session\.open, not key\.add/);

  // A scoped system key signs only what it is scoped to.
  const scoped: KeyInfo = { ...sys.info, role: "system", scope: { types: ["fee.paid"] } };
  const addScoped: HssEvent = { ...addSys, public: { key: scoped as never } };
  const st2 = await applyEvent(state, { event: addScoped, sig: await s.admin.sign(addScoped) });
  const fee: HssEvent = { hss: 1, issuer: "demo-city", seq: st2.head.seq + 1, prev: st2.head.hash, type: "fee.paid", ts: iso(s.t0 + H), public: { amount: "100" }, docs: [], actor: scoped.id };
  const st3 = await applyEvent(st2, { event: fee, sig: await sys.sign(fee) });
  const approve: HssEvent = { ...fee, seq: st3.head.seq + 1, prev: st3.head.hash, type: "permit.approve" };
  await assert.rejects(applyEvent(st3, { event: approve, sig: await sys.sign(approve) }), /may only sign fee\.paid/);
});

test("sessions: closed by owner, by itself or by an admin; revoking the person ends their sessions", async () => {
  for (const closer of ["owner", "self", "admin"] as const) {
    const s = await setup();
    const ses = await session8h(s);
    await s.add(s.official, { type: "session.open", public: { key: ses.info as never } });
    const by = closer === "owner" ? s.official : closer === "self" ? ses : s.admin;
    await s.add(by, { type: "session.close", public: { keyId: ses.info.id } });
    const state = (await replay(s.log)).state!;
    assert.ok(state.keys[ses.info.id].revokedAt !== undefined, closer);
    const after: HssEvent = { hss: 1, issuer: "demo-city", seq: state.head.seq + 1, prev: state.head.hash, type: "case.note", ts: iso(s.t0 + H), public: {}, docs: [], actor: ses.info.id };
    await assert.rejects(applyEvent(state, { event: after, sig: await ses.sign(after) }), /revoked/);
  }

  const s = await setup();
  const ses = await session8h(s);
  await s.add(s.official, { type: "session.open", public: { key: ses.info as never } });
  await s.add(s.admin, { type: "key.revoke", public: { keyId: s.official.info.id, reason: "left the office" } });
  const state = (await replay(s.log)).state!;
  assert.equal(state.keys[ses.info.id].revokedAt, state.head.seq);

  // Someone else's session cannot be closed by another official.
  const t = await setup();
  const ses2 = await session8h(t);
  const other = await ed25519Key("official", "Other official");
  await t.add(t.admin, { type: "key.add", public: { key: other.info as never } });
  await t.add(t.official, { type: "session.open", public: { key: ses2.info as never } });
  const st = (await replay(t.log)).state!;
  const close: HssEvent = { hss: 1, issuer: "demo-city", seq: st.head.seq + 1, prev: st.head.hash, type: "session.close", ts: iso(t.t0 + H), public: { keyId: ses2.info.id }, docs: [], actor: other.info.id };
  await assert.rejects(applyEvent(st, { event: close, sig: await other.sign(close) }), /closed by its owner/);
});

test("verifier: a session event first proven on Bitcoin long after the session expired is refused", async () => {
  const s = await setup();
  const ses = await session8h(s);
  await s.add(s.official, { type: "session.open", public: { key: ses.info as never } });
  const step = await s.add(ses, { type: "case.inspect", public: { result: "pass" } });
  const hash = await eventHashHex(step.event);
  const leaf = await leafOf("event", hex.decode(hash));
  const root = await rootOf([leaf]);
  const ts = newTimestamp(root);
  const tip = await addOp(await addOp(ts, { tag: 0xf0, arg: new Uint8Array(16) }), { tag: 0x08 });
  tip.attestations.push({ kind: "bitcoin", height: 900_000 });

  const proofAt = async (blockTimeMs: number) => {
    const fakeFetch = (async (url: string) => {
      const u = String(url);
      if (/block-height\/900000$/.test(u)) return new Response("00".repeat(32));
      if (/block\/0{64}$/.test(u)) return Response.json({ id: "00".repeat(32), height: 900000, merkle_root: hex.encode(reverse(tip.msg)), timestamp: Math.floor(blockTimeMs / 1000) });
      return new Response("", { status: 404 });
    }) as typeof fetch;
    const proof: HardStateProof = {
      hardstate: "proof", hss: 1, subject: { kind: "event", signed: step, hash }, authority: [s.log[0], s.log[1], s.log[4]],
      batch: { id: "b", closedAt: iso(s.t0), root: hex.encode(root), size: 1, index: 0, path: [] }, ots: b64.encode(serializeDetached(ts)), issuedAt: iso(Date.now()),
    };
    return verifyProof(proof, { fetch: fakeFetch });
  };
  assert.equal((await proofAt(s.t0 + 2 * H)).status, "valid");
  const late = await proofAt(s.t0 + 8 * H + 7 * H);
  assert.equal(late.status, "invalid");
  assert.equal(late.steps.find((x) => x.id === "signature")?.title, "Signed with an expired session");
});

test("authority chain: a session.open signed by a key the chain does not establish is refused", async () => {
  const s = await setup();
  const ses = await session8h(s);
  await s.add(s.official, { type: "session.open", public: { key: ses.info as never } });
  const step = await s.add(ses, { type: "case.inspect", public: {} });
  await assert.rejects(checkAuthority([s.log[0], s.log[4]], step.event), /not signed by a key established earlier/);
});
