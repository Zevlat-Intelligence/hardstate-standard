// verify.ts — the HardState Receipt verifier. Given a proof (and optionally the document) it rebuilds every link from
// the bytes up to a Bitcoin block, asking public explorers only for block headers and transactions. No HardState
// server is involved: the same function runs in the browser, in a Worker, or in a CLI.
//
// The verdict is "valid" only when the event is intact, signed by the key its proof declares, included in its batch,
// and that batch is in a confirmed Bitcoin block (through OpenTimestamps, the HardState Anchor, or both). Authority
// rules and log completeness are pluggable checks (`authority`, `replay`); the HardState Verifier supplies them.

import { b64, equal, hex, type Bytes } from "./bytes.ts";
import { blockAt, consensus, EXPLORERS, anchorScript, txInfo, type Network } from "./btc.ts";
import { docCommitment, eventHash, type HssEvent, type KeyInfo, type Signature, type SignedEvent } from "./event.ts";
import { attestations, deserializeDetached, merkleRootMatches } from "./ots.ts";
import { leafOf, proofRoot, type HardStateProof } from "./proof.ts";
import { userVerified, verifyEventSignature } from "./sig.ts";

export type StepId = "integrity" | "signature" | "batch" | "ots" | "anchor" | "document" | "log" | "absence" | "completeness" | "revocation";
export type StepState = "pass" | "fail" | "pending" | "skip";

export interface Step {
  id: StepId;
  state: StepState;
  title: string;
  detail: string;
  /** Machine-readable facts the UI can show (block height, signer label, txid…). */
  facts?: Record<string, string | number | boolean>;
}

export interface Verdict {
  status: "valid" | "pending" | "invalid";
  steps: Step[];
  /** Earliest Bitcoin block time that proves the event existed (unix seconds). */
  provenBefore?: number;
  subjectHash: string;
}

export interface VerifyOptions {
  fetch?: typeof fetch;
  explorers?: Partial<Record<Network, string[]>>;
  /** Check a document against the event's commitments: the file (or its sha256) and the salt from the receipt. */
  document?: { file?: Bytes; digest?: Bytes; salt: Bytes };
  /** The issuer's full log, to check the event sits in an unbroken chain and its signer was never revoked before it. */
  log?: SignedEvent[];
  /** Checks the proof's authority chain and returns the signer. Without it, the key the chain declares is used as is. */
  authority?: AuthorityCheck;
  /** Replays a full log. Without it, `log` is not checked. */
  replay?: LogReplay;
}

/** What the verdict says about who signed. */
export interface SignerView {
  title: string;
  detail: string;
  facts?: Record<string, string | number | boolean>;
}

/** The signer of an event as an authority check returns it. */
export interface Signer {
  info: KeyInfo;
  /** seq of the record that declared the key. */
  addedAt: number;
  /** How the verdict presents the signer once the signature verifies. */
  show?: (sig: Signature, origin?: string) => SignerView;
  /** The record must be proven on Bitcoin before `at` (unix ms); if it is proven later, the signature step fails. */
  deadline?: { at: number; late: (provenBefore: string) => SignerView };
}

export type AuthorityCheck = (chain: SignedEvent[], target: HssEvent) => Promise<Signer>;
export type LogReplay = (log: SignedEvent[]) => Promise<{ state: { head: { seq: number } } | null; error?: { seq: number; message: string } }>;

/** The key a proof's chain declares for the event's actor, without evaluating any authority rule. */
async function declaredKey(chain: SignedEvent[], target: HssEvent): Promise<Signer> {
  for (const s of chain) {
    const k = s.event.public?.key as unknown as KeyInfo | undefined;
    if (s.event.issuer === target.issuer && s.event.seq <= target.seq && k && typeof k === "object" && k.id === target.actor) {
      const addedAt = s.event.seq;
      return { info: k, addedAt, show: (sig, origin) => ({ title: "Signed by the declared key",
        detail: `The signature matches the key "${k.label}" declared at entry #${addedAt}. Authority rules were not evaluated by this verifier.`,
        facts: { signer: k.label, role: k.role, keyKind: k.kind, userVerified: userVerified(sig), ...(origin ? { origin } : {}) } }) };
    }
  }
  throw new Error(`the proof does not declare the key ${target.actor}`);
}

const msg = (e: unknown) => (e instanceof Error ? e.message : String(e));

export async function verifyReceipt(proof: HardStateProof, opts: VerifyOptions = {}): Promise<Verdict> {
  const steps: Step[] = [];
  const add = (s: Step) => { steps.push(s); return s; };
  let provenBefore: number | undefined;
  const seen = (t?: number) => { if (t && (provenBefore === undefined || t < provenBefore)) provenBefore = t; };

  if (proof.hardstate !== "proof" || proof.hss !== 1) {
    return { status: "invalid", subjectHash: "", steps: [{ id: "integrity", state: "fail", title: "Not a HardState Proof", detail: "Unknown format or version." }] };
  }

  // 1. Integrity: the bytes hash to what the proof claims.
  let subject: Bytes;
  const kind = proof.subject.kind;
  if (proof.subject.kind === "event") {
    subject = await eventHash(proof.subject.signed.event);
    const ok = hex.encode(subject) === proof.subject.hash;
    add({ id: "integrity", state: ok ? "pass" : "fail", title: "Record is intact",
      detail: ok ? "The record hashes to exactly the value that was anchored." : "The record was changed: its hash no longer matches.",
      facts: { hash: hex.encode(subject) } });
  } else {
    subject = hex.decode(proof.subject.digest);
    add({ id: "integrity", state: subject.length === 32 ? "pass" : "fail", title: "Fingerprint", detail: "A SHA-256 fingerprint stamped by a citizen or organization.", facts: { hash: proof.subject.digest } });
  }

  // 2. Signature (and, with an authority check, the issuer's authority rules). Events only.
  let deadline: Signer["deadline"];
  if (proof.subject.kind === "event") {
    const { event, sig } = proof.subject.signed;
    try {
      const signer = await (opts.authority ?? declaredKey)(proof.authority ?? [], event);
      const { origin } = await verifyEventSignature(event, sig, signer.info);
      const view = signer.show?.(sig, origin) ?? { title: "Signed", detail: `Signed by the key "${signer.info.label}".` };
      add({ id: "signature", state: "pass", ...view });
      deadline = signer.deadline;
    } catch (e) {
      add({ id: "signature", state: "fail", title: "Signature", detail: msg(e) });
    }
  }

  // 3. Inclusion in the batch.
  let batchRoot: Bytes | undefined;
  if (!proof.batch) {
    add({ id: "batch", state: "pending", title: "Waiting for the next batch", detail: "Records are grouped every 10 minutes before being timestamped on Bitcoin." });
  } else {
    try {
      const b = proof.batch;
      const root = await proofRoot(await leafOf(kind, subject), b);
      if (!equal(root, hex.decode(b.root))) throw new Error("the inclusion path does not lead to the batch root");
      batchRoot = root;
      add({ id: "batch", state: "pass", title: "Included in batch", detail: b.index !== undefined && b.size !== undefined ? `Entry ${b.index + 1} of ${b.size} in batch ${b.id}.` : `The record is in batch ${b.id}.`, facts: { batch: b.id, root: b.root } });
    } catch (e) {
      add({ id: "batch", state: "fail", title: "Batch inclusion", detail: msg(e) });
    }
  }

  // 4–5. Bitcoin: OpenTimestamps and the HardState Anchor.
  await bitcoinSteps(batchRoot, proof, opts, add, seen);

  // 6. The document the citizen holds.
  if (opts.document && proof.subject.kind === "event") {
    try {
      const digest = opts.document.digest ?? (opts.document.file ? new Uint8Array(await crypto.subtle.digest("SHA-256", opts.document.file)) : undefined);
      if (!digest) throw new Error("no document given");
      const c = hex.encode(await docCommitment(digest, opts.document.salt));
      const doc = proof.subject.signed.event.docs.find((d) => d.commitment === c);
      add(doc
        ? { id: "document", state: "pass", title: "Document matches", detail: `This file is exactly "${doc.label}" as recorded.`, facts: { label: doc.label } }
        : { id: "document", state: "fail", title: "Document does not match", detail: "This file is not the one recorded in this event (or the receipt's key is wrong)." });
    } catch (e) {
      add({ id: "document", state: "fail", title: "Document", detail: msg(e) });
    }
  }

  // 7. Completeness: the issuer's full log is an unbroken chain that contains this exact event.
  if (opts.log && opts.replay && proof.subject.kind === "event") {
    const ev = proof.subject.signed.event;
    const r = await opts.replay(opts.log);
    const at = opts.log.find((s) => s.event.seq === ev.seq);
    const same = at ? hex.encode(await eventHash(at.event)) === proof.subject.hash : false;
    if (r.error && r.error.seq <= ev.seq) {
      add({ id: "log", state: "fail", title: "Institution log is broken", detail: `Entry #${r.error.seq}: ${r.error.message}` });
    } else if (!same) {
      add({ id: "log", state: "fail", title: "Record missing from the log", detail: `The institution's log does not hold this record at entry #${ev.seq}: it was removed or replaced.` });
    } else {
      add({ id: "log", state: "pass", title: "Log is complete", detail: `Entries #0–#${r.state?.head.seq} form an unbroken signed chain; nothing before this record was deleted or reordered.`,
        facts: { head: r.state?.head.seq ?? 0, ...(r.error ? { laterProblem: r.error.seq } : {}) } });
    }
  }

  // A key whose validity has ended could still sign back-dated records; Bitcoin bounds when the record existed, so a
  // record first proven after the signer's deadline is refused.
  if (deadline && provenBefore !== undefined && provenBefore * 1000 > deadline.at) {
    const sigStep = steps.find((s) => s.id === "signature");
    if (sigStep) Object.assign(sigStep, { state: "fail", ...deadline.late(new Date(provenBefore * 1000).toISOString()) });
  }

  const failed = steps.some((s) => s.state === "fail");
  const onChain = steps.some((s) => (s.id === "ots" || (s.id === "anchor" && proof.anchor?.network === "bitcoin")) && s.state === "pass");
  return { status: failed ? "invalid" : onChain ? "valid" : "pending", steps, provenBefore, subjectHash: hex.encode(subject) };
}

/** Steps 4 and 5, shared by every proof that ends in a batch root: the batch's OpenTimestamps proof against Bitcoin
 * block headers, and its HardState Anchor transaction. Both are read from at least two explorers that must agree. */
export async function bitcoinSteps(batchRoot: Bytes | undefined, proof: Pick<HardStateProof, "ots" | "anchor">, opts: VerifyOptions,
  add: (s: Step) => Step, seen: (t?: number) => void): Promise<void> {
  const f = opts.fetch ?? fetch;
  const explorers = (n: Network) => opts.explorers?.[n] ?? EXPLORERS[n];
  // OpenTimestamps → Bitcoin block header.
  if (!proof.ots) {
    add({ id: "ots", state: batchRoot ? "pending" : "skip", title: "OpenTimestamps", detail: "Not submitted yet." });
  } else if (batchRoot) {
    try {
      const ts = await deserializeDetached(b64.decode(proof.ots));
      if (!equal(ts.msg, batchRoot)) throw new Error("the .ots proof is for a different root");
      const btc = [...attestations(ts)].filter((a) => a.att.kind === "bitcoin");
      if (!btc.length) {
        add({ id: "ots", state: "pending", title: "Timestamp pending", detail: "Calendars have committed to it; Bitcoin confirmation usually takes 1–3 hours." });
      } else {
        let best: { height: number; hash: string; time: number; sources: string[] } | undefined;
        const errors: string[] = [];
        for (const a of btc) {
          const height = (a.att as { height: number }).height;
          try {
            const { value: block, sources } = await consensus(explorers("bitcoin"), (base) => blockAt(base, height, f), (bl) => bl.merkleRoot);
            if (!merkleRootMatches(a.msg, block.merkleRoot)) throw new Error(`does not match block ${height}'s merkle root`);
            if (!best || block.time < best.time) best = { height, hash: block.hash, time: block.time, sources };
          } catch (e) { errors.push(`block ${height}: ${msg(e)}`); }
        }
        if (!best) throw new Error(errors.join("; "));
        seen(best.time);
        add({ id: "ots", state: "pass", title: "Timestamped on Bitcoin", detail: `Committed in Bitcoin block ${best.height} (${new Date(best.time * 1000).toISOString()}) via OpenTimestamps.`,
          facts: { height: best.height, time: best.time, blockHash: best.hash, explorers: best.sources.length } });
      }
    } catch (e) {
      add({ id: "ots", state: "fail", title: "OpenTimestamps", detail: msg(e) });
    }
  }

  // HardState Anchor: the daily OP_RETURN.
  if (!proof.anchor) {
    add({ id: "anchor", state: batchRoot ? "pending" : "skip", title: "HardState Anchor", detail: "Batches are also written to Bitcoin in HardState's own daily transaction." });
  } else if (batchRoot) {
    const a = proof.anchor;
    try {
      const root = await proofRoot(await leafOf("batch", batchRoot), a);
      if (!equal(root, hex.decode(a.root))) throw new Error("the batch is not in this anchor");
      const script = hex.encode(anchorScript(root));
      const { value: tx, sources } = await consensus(explorers(a.network), (base) => txInfo(base, a.txid, f), (t) => `${t.confirmed}:${t.blockHash ?? ""}:${t.opReturns.join(",")}`);
      if (!tx.opReturns.includes(script)) throw new Error("transaction does not carry this root");
      if (!tx.confirmed) {
        add({ id: "anchor", state: "pending", title: "Anchor broadcast", detail: "The transaction is in the mempool, waiting for a block.", facts: { txid: a.txid, network: a.network } });
      } else {
        if (a.network === "bitcoin") seen(tx.blockTime);
        add({ id: "anchor", state: "pass", title: a.network === "bitcoin" ? "Anchored in Bitcoin" : "Anchored on signet (test network)",
          detail: `Root written in transaction ${a.txid.slice(0, 12)}… in block ${tx.blockHeight}.`,
          facts: { txid: a.txid, network: a.network, height: tx.blockHeight ?? 0, time: tx.blockTime ?? 0, ...(tx.blockHash ? { blockHash: tx.blockHash } : {}), explorers: sources.length } });
      }
    } catch (e) {
      add({ id: "anchor", state: "fail", title: "HardState Anchor", detail: msg(e) });
    }
  }

}
