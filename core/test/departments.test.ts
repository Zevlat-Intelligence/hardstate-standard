import { test } from "node:test";
import assert from "node:assert/strict";
import { checkAuthority, eventHashHex, replay, type HssEvent, type KeyInfo, type SignedEvent } from "../src/index.ts";
import { demoLog, ed25519Key, type TestKey } from "./helpers.ts";

/** demoLog plus two departments: Permits (any type) with a head, and Treasury (fee.* only) with an official. */
async function setup() {
  const demo = await demoLog();
  const log = [...demo.log];
  const t0 = Date.parse(log[log.length - 1].event.ts) + 60_000;
  const add = async (signer: TestKey, partial: Partial<HssEvent> & { type: string }) => {
    const event: HssEvent = { hss: 1, issuer: "demo-city", seq: log.length, prev: await eventHashHex(log[log.length - 1].event), ts: new Date(t0 + log.length * 60_000).toISOString(), actor: signer.info.id, public: {}, docs: [], ...partial };
    const s: SignedEvent = { event, sig: await signer.sign(event) };
    log.push(s);
    return s;
  };
  const key = async (role: KeyInfo["role"], label: string, dept?: string, extra: Partial<KeyInfo> = {}) => {
    const k = await ed25519Key(role, label);
    k.info = { ...k.info, ...(dept ? { dept } : {}), ...extra };
    return k;
  };
  const { admin } = demo;
  await add(admin, { type: "dept.add", public: { dept: { id: "permits", name: "Permits" } } });
  await add(admin, { type: "dept.add", public: { dept: { id: "treasury", name: "Treasury", types: ["fee.*"] } } });
  const head = await key("admin", "Rosa Vega — Head of Permits", "permits");
  await add(admin, { type: "key.add", public: { key: head.info as never } });
  const cashier = await key("official", "Luis Mar — Cashier", "treasury");
  await add(admin, { type: "key.add", public: { key: cashier.info as never } });
  return { ...demo, log, add, key, head, cashier };
}

const ok = async (log: SignedEvent[]) => assert.equal((await replay(log)).error, undefined);
const fails = async (log: SignedEvent[], pattern: RegExp) => {
  const r = await replay(log);
  assert.ok(r.error, "expected the log to break");
  assert.match(r.error!.message, pattern);
};

test("departments: declared by an institution admin; a head adds keys to their own department only", async () => {
  const s = await setup();
  await ok(s.log);
  const inspector = await s.key("official", "Ana Paz — Inspector", "permits");
  await s.add(s.head, { type: "key.add", public: { key: inspector.info as never } });
  await s.add(inspector, { type: "case.inspect", case: "BP-1", public: {} });
  await ok(s.log);
  const state = (await replay(s.log)).state!;
  assert.equal(state.keys[inspector.info.id].dept, "permits");
  assert.equal(state.depts.treasury.types?.[0], "fee.*");

  const intruder = await s.key("official", "Sam Ruiz", "treasury");
  await s.add(s.head, { type: "key.add", public: { key: intruder.info as never } });
  await fails(s.log, /heads Permits and may only add keys in it or under it/);
});

test("departments: a head cannot open top-level departments, move keys from elsewhere, update the profile or reach other departments", async () => {
  const attempts: [Partial<HssEvent> & { type: string }, RegExp][] = [
    [{ type: "dept.add", public: { dept: { id: "parks", name: "Parks" } } }, /may only open departments in it or under it/],
    [{ type: "dept.add", public: { dept: { id: "tills", name: "Tills", parent: "treasury" } } }, /may only open departments in it or under it/],
    [{ type: "issuer.update", public: { website: "https://example.org" } }, /needs an institution admin key/],
    [{ type: "dept.update", public: { dept: { id: "permits", types: ["case.*"] } } }, /may only change the departments under it/],
  ];
  for (const [partial, why] of attempts) {
    const s = await setup();
    await s.add(s.head, partial);
    await fails(s.log, why);
  }
  const s = await setup();
  await s.add(s.head, { type: "key.move", public: { keyId: s.cashier.info.id, dept: "permits" } });
  await fails(s.log, /may only move keys in it or under it/);
  const r = await setup();
  await r.add(r.head, { type: "key.revoke", public: { keyId: r.cashier.info.id } });
  await fails(r.log, /may only revoke keys in it/);
});

test("departments: a department's types bind its keys and their sessions; key.move changes what they may sign", async () => {
  const s = await setup();
  await s.add(s.cashier, { type: "fee.paid", case: "BP-1", public: {} });
  await ok(s.log);
  await s.add(s.cashier, { type: "permit.approve", case: "BP-1", public: {} });
  await fails(s.log, /signs for Treasury, which may only sign fee\.\*/);

  // A session takes its person's department.
  const t = await setup();
  const sess = await ed25519Key("official", "Cashier's till");
  sess.info = { ...sess.info, role: "session", scope: { expires: new Date(Date.parse(t.log[t.log.length - 1].event.ts) + 3_600_000 * 4).toISOString() } };
  await t.add(t.cashier, { type: "session.open", public: { key: sess.info as never } });
  await t.add(sess, { type: "fee.paid", public: {} });
  await ok(t.log);
  await t.add(sess, { type: "case.open", public: {} });
  await fails(t.log, /which may only sign fee\.\*/);

  // Moved to Permits, the same person signs a permit.
  const m = await setup();
  await m.add(m.admin, { type: "key.move", public: { keyId: m.cashier.info.id, dept: "permits" } });
  await m.add(m.cashier, { type: "permit.approve", case: "BP-1", public: {} });
  await ok(m.log);
  assert.equal((await replay(m.log)).state!.keys[m.cashier.info.id].dept, "permits");
});

test("departments: closing needs it empty; the reserved domains stay the protocol's", async () => {
  const s = await setup();
  await s.add(s.admin, { type: "dept.update", public: { dept: { id: "treasury", closed: true } } });
  await fails(s.log, /closes only once it has no active keys/);

  const c = await setup();
  await c.add(c.admin, { type: "key.revoke", public: { keyId: c.cashier.info.id } });
  await c.add(c.admin, { type: "dept.update", public: { dept: { id: "treasury", closed: true } } });
  await ok(c.log);
  const late = await c.key("official", "Too late", "treasury");
  await c.add(c.admin, { type: "key.add", public: { key: late.info as never } });
  await fails(c.log, /no open department treasury/);

  const r = await setup();
  await r.add(r.admin, { type: "dept.audit", public: {} });
  await fails(r.log, /dept\.audit cannot be signed here/);
  const scoped = await setup();
  await scoped.add(scoped.admin, { type: "dept.add", public: { dept: { id: "it", name: "IT", types: ["key.*"] } } });
  await fails(scoped.log, /cannot grant/);
});

test("departments: the last institution admin cannot be moved into a department", async () => {
  const s = await setup();
  await s.add(s.admin, { type: "key.move", public: { keyId: s.admin.info.id, dept: "permits" } });
  await fails(s.log, /last institution admin/);
});

test("authority chain: carries the department, and its scope, without the full log", async () => {
  const s = await setup();
  const inspector = await s.key("official", "Ana Paz — Inspector", "permits");
  await s.add(s.head, { type: "key.add", public: { key: inspector.info as never } });
  const step = await s.add(inspector, { type: "case.inspect", public: {} });
  const fee = await s.add(s.cashier, { type: "permit.approve", public: {} });
  // What proofs.ts sends: issuer.create, the dept events, the key.adds that reach the signer.
  const chainFor = (signerAddSeqs: number[]) => s.log.filter((e) => e.event.seq === 0 || ["dept.add", "dept.update", "key.move"].includes(e.event.type) || signerAddSeqs.includes(e.event.seq));
  const a = await checkAuthority(chainFor([s.log.findIndex((e) => (e.event.public.key as { id?: string } | undefined)?.id === s.head.info.id), s.log.findIndex((e) => (e.event.public.key as { id?: string } | undefined)?.id === inspector.info.id)]), step.event);
  assert.equal(a.department?.name, "Permits");
  await assert.rejects(checkAuthority(chainFor([s.log.findIndex((e) => (e.event.public.key as { id?: string } | undefined)?.id === s.cashier.info.id)]), fee.event), /may only sign fee\.\*/);
});

test("sub-departments: a head opens them under theirs and manages the whole branch; limits apply all the way up", async () => {
  const s = await setup();
  await s.add(s.head, { type: "dept.add", public: { dept: { id: "inspections", name: "Inspections", parent: "permits", types: ["case.*"] } } });
  await s.add(s.head, { type: "dept.add", public: { dept: { id: "night-shift", name: "Night shift", parent: "inspections" } } });
  const inspector = await s.key("official", "Ana Paz — Inspector", "night-shift");
  await s.add(s.head, { type: "key.add", public: { key: inspector.info as never } });
  await s.add(inspector, { type: "case.inspect", case: "BP-1", public: {} });
  await s.add(s.head, { type: "key.move", public: { keyId: inspector.info.id, dept: "inspections" } });
  await s.add(s.head, { type: "dept.update", public: { dept: { id: "night-shift", closed: true } } });
  await s.add(s.head, { type: "key.revoke", public: { keyId: inspector.info.id } });
  await ok(s.log);
  const state = (await replay(s.log)).state!;
  assert.equal(state.depts["night-shift"].parent, "inspections");
  assert.equal(state.depts["night-shift"].closedAt !== undefined, true);

  // Treasury allows only fee.*: a unit under it cannot widen that with its own types.
  const t = await setup();
  await t.add(t.admin, { type: "dept.add", public: { dept: { id: "tills", name: "Tills", parent: "treasury", types: ["fee.*", "permit.*"] } } });
  const till = await t.key("official", "Till 3", "tills");
  await t.add(t.admin, { type: "key.add", public: { key: till.info as never } });
  await t.add(till, { type: "fee.paid", public: {} });
  await ok(t.log);
  await t.add(till, { type: "permit.approve", public: {} });
  await fails(t.log, /signs for Treasury, which may only sign fee\.\*/);
});

test("sub-departments: at most four levels; a parent closes only after its children; places are permanent", async () => {
  const s = await setup();
  let parent = "permits";
  for (const id of ["a", "b", "c"]) {
    await s.add(s.admin, { type: "dept.add", public: { dept: { id, name: id.toUpperCase(), parent } } });
    parent = id;
  }
  await ok(s.log);
  await s.add(s.admin, { type: "dept.add", public: { dept: { id: "d", name: "D", parent: "c" } } });
  await fails(s.log, /at most 4 levels/);

  const c = await setup();
  await c.add(c.admin, { type: "dept.add", public: { dept: { id: "unit", name: "Unit", parent: "permits" } } });
  await c.add(c.admin, { type: "key.revoke", public: { keyId: c.head.info.id } });
  await c.add(c.admin, { type: "dept.update", public: { dept: { id: "permits", closed: true } } });
  await fails(c.log, /once the departments under it are closed/);

  const m = await setup();
  await m.add(m.admin, { type: "dept.update", public: { dept: { id: "treasury", parent: "permits" } } });
  await fails(m.log, /keeps the place its dept.add gave it/);
});

test("authority chain: a key in a sub-department is checked against every department above it", async () => {
  const s = await setup();
  await s.add(s.admin, { type: "dept.add", public: { dept: { id: "tills", name: "Tills", parent: "treasury" } } });
  const till = await s.key("official", "Till 3", "tills");
  await s.add(s.admin, { type: "key.add", public: { key: till.info as never } });
  const fee = await s.add(till, { type: "fee.paid", public: {} });
  const bad = await s.add(till, { type: "case.open", public: {} });
  const chain = s.log.filter((e) => e.event.seq === 0 || ["dept.add", "dept.update", "key.move"].includes(e.event.type) || (e.event.public.key as { id?: string } | undefined)?.id === till.info.id);
  assert.equal((await checkAuthority(chain, fee.event)).department?.name, "Tills");
  await assert.rejects(checkAuthority(chain, bad.event), /Treasury, which may only sign fee\.\*/);
});
