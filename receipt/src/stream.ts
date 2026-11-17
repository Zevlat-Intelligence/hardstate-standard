// stream.ts — completeness of an AI system's stream of records. Each heartbeat (ai.heartbeat) states what the process
// that signs it recorded since its previous beat: how many decisions, runs and failures, and a running digest over
// the hashes of those very records. Given the two beats and the slice of the institution's log between them, anyone
// recomputes both: a record that was never written, or written and then hidden, makes them disagree; a beat that
// came late shows a gap in the logging itself.

import { concat, hex, sha256, utf8, type Bytes } from "./bytes.ts";
import { eventHash, type SignedEvent } from "./event.ts";

const STREAM_DOMAIN = utf8("hardstate/ai-stream/v1");

/** Where a stream digest starts after each beat. */
export const STREAM_START = new Uint8Array(32);

/** One record into the digest: sha256("hardstate/ai-stream/v1" ‖ acc ‖ record hash). */
export const streamStep = (acc: Bytes, recordHash: Bytes) => sha256(concat(STREAM_DOMAIN, acc, recordHash));

/** The digest over record hashes, in log order, from STREAM_START. */
export async function streamDigest(hashes: Bytes[]): Promise<Bytes> {
  let acc: Bytes = STREAM_START;
  for (const h of hashes) acc = await streamStep(acc, h);
  return acc;
}

export type StreamState = "complete" | "missing" | "gap" | "unlinked";

export interface StreamResult {
  state: StreamState;
  detail: string;
  facts: Record<string, string | number | boolean>;
}

const HEARTBEAT = "ai.heartbeat";

/** The records of one process in a slice of the log: signed by `actor`, carrying its `instance`, not its beats. */
export const streamRecords = (segment: SignedEvent[], actor: string, instance: string) =>
  segment.filter((s) => s.event.actor === actor && s.event.public?.instance === instance && s.event.type !== HEARTBEAT);

/**
 * Checks one window of a process's stream: `prev` and `beat` are consecutive heartbeats of the same process, and
 * `segment` is every entry of the institution's log strictly between them, in order (taken from the log, which is
 * signed and chained). The window is "complete" when the slice links the two beats entry by entry and the records of
 * that process in it match the beat's counts and digest; "missing" when they do not; "gap" when the beat came later
 * than twice its interval; "unlinked" when the beats or the slice do not fit together.
 */
export async function verifyStream(prev: SignedEvent, beat: SignedEvent, segment: SignedEvent[]): Promise<StreamResult> {
  const b = beat.event, p = prev.event;
  const instance = typeof b.public.instance === "string" ? b.public.instance : "";
  const base = { from: p.seq, to: b.seq, instance };
  const unlinked = (detail: string): StreamResult => ({ state: "unlinked", detail, facts: base });

  if (b.type !== HEARTBEAT || p.type !== HEARTBEAT) return unlinked("Both ends of a window must be heartbeats.");
  if (b.issuer !== p.issuer || b.actor !== p.actor || p.public.instance !== b.public.instance) return unlinked("The two heartbeats belong to different processes.");
  if (b.public.since !== p.seq) return unlinked(`The heartbeat at entry #${b.seq} does not point to the one at entry #${p.seq}.`);
  if (b.seq <= p.seq || segment.length !== b.seq - p.seq - 1) return unlinked(`Entries #${p.seq + 1}–#${b.seq - 1} are not all here.`);

  // The slice links the two beats entry by entry: nothing in between can be swapped or left out.
  let link = hex.encode(await eventHash(p));
  for (let i = 0; i < segment.length; i++) {
    const e = segment[i].event;
    if (e.issuer !== b.issuer || e.seq !== p.seq + 1 + i || e.prev !== link) return unlinked(`Entry #${p.seq + 1 + i} does not follow the one before it.`);
    link = hex.encode(await eventHash(e));
  }
  if (b.prev !== link) return unlinked(`The heartbeat at entry #${b.seq} does not follow entry #${b.seq - 1}.`);

  const own = streamRecords(segment, b.actor, instance);
  const found = {
    decisions: own.filter((s) => s.event.type === "ai.decision").length,
    runs: own.filter((s) => s.event.type === "ai.run").length,
    failures: own.filter((s) => s.event.type === "ai.run" && s.event.public.outcome === "failed").length,
  };
  const facts: StreamResult["facts"] = { ...base, records: own.length, ...found };

  for (const k of ["decisions", "runs", "failures"] as const) {
    const said = b.public[k];
    if (typeof said === "number" && said !== found[k]) {
      return { state: "missing", detail: `The heartbeat at entry #${b.seq} counts ${said} ${k}, but the log holds ${found[k]} between entries #${p.seq} and #${b.seq}.`, facts: { ...facts, [`said_${k}`]: said } };
    }
  }
  if (typeof b.public.digest === "string") {
    const digest = hex.encode(await streamDigest(await Promise.all(own.map((s) => eventHash(s.event)))));
    if (digest !== b.public.digest) {
      return { state: "missing", detail: `The records between entries #${p.seq} and #${b.seq} are not the ones the heartbeat at entry #${b.seq} vouches for.`, facts: { ...facts, digest: false } };
    }
    facts.digest = true;
  }
  const every = typeof b.public.every === "number" && b.public.every > 0 ? b.public.every : null;
  if (every && Date.parse(b.ts) - Date.parse(p.ts) > 2 * every * 1000) {
    return { state: "gap", detail: `The heartbeat at entry #${b.seq} came ${Math.round((Date.parse(b.ts) - Date.parse(p.ts)) / 60_000)} minutes after the previous one, more than twice its interval: the logging stopped in between.`, facts: { ...facts, every } };
  }
  return { state: "complete", detail: `Between entries #${p.seq} and #${b.seq} the log holds exactly the ${own.length} records this process vouched for.`, facts };
}
