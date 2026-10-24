// operator.test.ts — signed operator requests: an admin's key signs a domain-separated hash; neither an event nor a
// request signature can stand in for the other.

import { test } from "node:test";
import assert from "node:assert/strict";
import { eventHash, operatorHash, operatorRequest, verifyEventSignature, verifyHashSignature, type HssEvent } from "../src/index.ts";
import { ed25519Key, passkey } from "./helpers.ts";

test("operator requests: passkey and Ed25519 signatures verify over the request hash", async () => {
  for (const k of [await passkey("admin", "Registrar"), await ed25519Key("admin", "Billing system")]) {
    const r = operatorRequest("billing.checkout", "demo-city", k.info.id, { plan: "professional", interval: "year" });
    const sig = await k.signHash(await operatorHash(r));
    await verifyHashSignature(await operatorHash(r), sig, k.info);
    const changed = { ...r, params: { plan: "institution", interval: "year" } };
    await assert.rejects(verifyHashSignature(await operatorHash(changed), sig, k.info));
  }
});

test("operator requests: domain-separated from events, fresh nonce each time", async () => {
  const k = await passkey("admin", "Registrar");
  const r = operatorRequest("billing.portal", "demo-city", k.info.id);
  const ev: HssEvent = { hss: 1, issuer: "demo-city", seq: 1, prev: "00".repeat(32), type: "case.open", ts: r.ts, actor: k.info.id, public: {}, docs: [] };
  // A request signature is not an event signature, and the other way round.
  await assert.rejects(verifyEventSignature(ev, await k.signHash(await operatorHash(r)), k.info), /challenge mismatch/);
  await assert.rejects(verifyHashSignature(await operatorHash(r), await k.signHash(await eventHash(ev)), k.info), /challenge mismatch/);
  assert.notEqual(operatorRequest("billing.portal", "demo-city", k.info.id).nonce, r.nonce);
});
