// ots-live.ts — checks the OpenTimestamps code against the real world:
//   1. verifies the reference client's own example proof (hello-world.txt.ots) against Bitcoin through two explorers;
//   2. stamps a fresh digest on the public calendars and writes the .ots so `ots info` / `ots verify` can read it.
// Usage: node scripts/ots-live.ts [outDir]

import { writeFileSync } from "node:fs";
import { attestations, blockAt, consensus, deserializeDetached, EXPLORERS, hex, merkleRootMatches, randomBytes, serializeDetached, sha256, stamp } from "../src/index.ts";

const RAW = "https://raw.githubusercontent.com/opentimestamps/opentimestamps-client/master/examples";
const out = process.argv[2] ?? ".";

const [ots, txt] = await Promise.all([fetch(`${RAW}/hello-world.txt.ots`), fetch(`${RAW}/hello-world.txt`)]);
const ts = await deserializeDetached(new Uint8Array(await ots.arrayBuffer()));
const digest = await sha256(new Uint8Array(await txt.arrayBuffer()));
console.log("hello-world.txt digest matches .ots:", hex.encode(digest) === hex.encode(ts.msg));
for (const a of attestations(ts)) {
  if (a.att.kind !== "bitcoin") { console.log("  attestation:", a.att); continue; }
  const { value: b, sources } = await consensus(EXPLORERS.bitcoin, (base) => blockAt(base, (a.att as { height: number }).height), (x) => x.merkleRoot);
  console.log(`  bitcoin block ${b.height}: merkle root matches = ${merkleRootMatches(a.msg, b.merkleRoot)} (${new Date(b.time * 1000).toISOString()}, ${sources.length} explorers)`);
}

const fresh = randomBytes(32);
const stamped = await stamp(fresh, { min: 2 });
const file = `${out}/fresh-${hex.encode(fresh).slice(0, 8)}.ots`;
writeFileSync(file, serializeDetached(stamped));
console.log("stamped", hex.encode(fresh), "→", file);
for (const a of attestations(stamped)) console.log("  ", a.att);
