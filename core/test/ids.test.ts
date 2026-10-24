import { test } from "node:test";
import assert from "node:assert/strict";
import { applyEvent, checkAuthority, commitHolder, eventHashHex, hex, holderCommitment, keyCode, normalizeKeyCode, replay, type HssEvent, type SignedEvent } from "../src/index.ts";
import { demoLog, ed25519Key, type TestKey } from "./helpers.ts";

test("key codes: six Crockford characters, stable, per institution", async () => {
  const a = await keyCode("demo-city", "ed25519:0123456789abcdef0123456789abcdef");
  assert.match(a, /^[0-9A-HJKMNP-TV-Z]{6}$/);
  assert.equal(await keyCode("demo-city", "ed25519:0123456789abcdef0123456789abcdef"), a);
  assert.notEqual(await keyCode("other-city", "ed25519:0123456789abcdef0123456789abcdef"), a);
  assert.equal(normalizeKeyCode(` ${a.slice(0, 3).toLowerCase()}-${a.slice(3)} `), a);
  assert.equal(normalizeKeyCode("D1ZSXO"), "D1ZSX0"); // O reads as zero
  assert.equal(normalizeKeyCode("toolong1"), null);
});

test("holder: a salted commitment to the name; the right name and salt open it, nothing else does", async () => {
  const { salt, holder } = await commitHolder("Ana  López ");
  assert.match(holder, /^[0-9a-f]{64}$/);
  assert.equal(await holderCommitment("Ana López", hex.decode(salt)), holder);
  assert.notEqual(await holderCommitment("Ana Lopez", hex.decode(salt)), holder);
  assert.notEqual(await holderCommitment("Ana López", new Uint8Array(16)), holder);
});

async function withLog() {
  const demo = await demoLog();
  const log = [...demo.log];
  const add = async (signer: TestKey, partial: Partial<HssEvent> & { type: string }) => {
    const event: HssEvent = { hss: 1, issuer: "demo-city", seq: log.length, prev: await eventHashHex(log[log.length - 1].event), ts: new Date(Date.UTC(2026, 9, 21, 9, log.length)).toISOString(), actor: signer.info.id, public: {}, docs: [], ...partial };
    const s: SignedEvent = { event, sig: await signer.sign(event) };
    log.push(s);
    return s;
  };
  return { ...demo, log, add };
}

test("log: every key gets its code; a code already in use is refused; only people commit to a holder", async () => {
  const s = await withLog();
  const inspector = await ed25519Key("official", "Building inspector");
  inspector.info = { ...inspector.info, holder: (await commitHolder("Luis Mar")).holder };
  await s.add(s.admin, { type: "key.add", public: { key: inspector.info as never } });
  const state = (await replay(s.log)).state!;
  assert.equal(state.keys[inspector.info.id].code, await keyCode("demo-city", inspector.info.id));

  // A collision is ~1 in a billion per pair; force one by giving an existing key the newcomer's code.
  const late = await ed25519Key("official", "Clerk");
  const step = await s.add(s.admin, { type: "key.add", public: { key: late.info as never } });
  const forged = { ...state, keys: { ...state.keys, [inspector.info.id]: { ...state.keys[inspector.info.id], code: await keyCode("demo-city", late.info.id) } } };
  await assert.rejects(applyEvent(forged, step), /key code .* is already taken/);

  const t = await withLog();
  const gateway = await ed25519Key("system", "Payments gateway");
  gateway.info = { ...gateway.info, scope: { types: ["fee.paid"] }, holder: "00".repeat(32) };
  await t.add(t.admin, { type: "key.add", public: { key: gateway.info as never } });
  assert.match((await replay(t.log)).error!.message, /only a person's key commits to its holder/);
});

test("authority chain: the signer comes back with its code, never more than the log says", async () => {
  const s = await withLog();
  const step = s.log[2];
  const signer = await checkAuthority(s.log.slice(0, 2), step.event);
  assert.equal(signer.code, await keyCode("demo-city", s.official.info.id));
});
