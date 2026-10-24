// verify.ts — the HardState Verifier. Given a proof (and optionally the document and the issuer's full log) it rebuilds
// every link from the bytes up to a Bitcoin block, asking public explorers only for block headers and transactions.
// No HardState server is involved: the same function runs in the browser, in a Worker, or in a CLI.
//
// The verdict is "valid" only when the event is intact, signed by a key the issuer's own log authorizes, included in
// its batch, and that batch is in a confirmed Bitcoin block (through OpenTimestamps, the HardState Anchor, or both).

import { b64, equal, hex, type Bytes } from "./bytes.ts";
import { blockAt, consensus, EXPLORERS, anchorScript, txInfo, type Network } from "./btc.ts";
import { docCommitment, eventHash, type SignedEvent } from "./event.ts";
import { checkAuthority, replay } from "./log.ts";
import { rootFromPath } from "./merkle.ts";
import { attestations, deserializeDetached, merkleRootMatches } from "./ots.ts";
import { leafOf, type HardStateProof } from "./proof.ts";
import { userVerified, verifyEventSignature } from "./sig.ts";

export type StepId = "integrity" | "signature" | "batch" | "ots" | "anchor" | "document" | "log";
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
}

/** How long after a session expires its last events may still reach Bitcoin (batching + OpenTimestamps delay). */
export const SESSION_ANCHOR_GRACE_MS = 6 * 3_600_000;

const msg = (e: unknown) => (e instanceof Error ? e.message : String(e));

export async function verifyProof(proof: HardStateProof, opts: VerifyOptions = {}): Promise<Verdict> {
  const f = opts.fetch ?? fetch;
  const explorers = (n: Network) => opts.explorers?.[n] ?? EXPLORERS[n];
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

  // 2. Signature and authority (events only).
  let sessionExpires: string | undefined;
  if (proof.subject.kind === "event") {
    const { event, sig } = proof.subject.signed;
    try {
      const signer = await checkAuthority(proof.authority ?? [], event);
      const { origin } = await verifyEventSignature(event, sig, signer.info);
      const d = signer.delegator;
      const dept = signer.department;
      // Who acted, as the public may know it: a code, a title and a department, never a person's name (HSS-1 §5.1).
      const as = (k: typeof signer) => `${k.info.role === "system" ? "system" : k.info.role === "admin" ? (k.dept ? "department head" : "admin") : "official"} ${k.code ?? ""} (${[k.info.label, dept?.name].filter(Boolean).join(", ")})`.replace("  ", " ");
      const deptFacts: Record<string, string> = dept ? { department: dept.name, departmentId: dept.id } : {};
      if (d) {
        // A delegated session: the person is who answers for it.
        sessionExpires = signer.info.scope?.expires;
        add({ id: "signature", state: "pass", title: "Signed on behalf of an authorized official",
          detail: `Signed on behalf of ${as(d)} through the session "${signer.info.label}", opened at entry #${signer.addedAt}, which expires ${sessionExpires}.`,
          facts: { signer: d.info.label, signerCode: d.code ?? "", role: d.info.role, ...deptFacts, keyKind: "session", session: signer.info.label, sessionExpires: sessionExpires ?? "", delegatedAt: signer.addedAt } });
      } else {
        add({ id: "signature", state: "pass", title: signer.info.role === "system" ? "Signed by an authorized system" : "Signed by an authorized official",
          detail: `Signed by ${as(signer)}, a key the institution registered in its own log at entry #${signer.addedAt}.`,
          facts: { signer: signer.info.label, signerCode: signer.code ?? "", role: signer.info.role, ...deptFacts, keyKind: signer.info.kind, userVerified: userVerified(sig), ...(origin ? { origin } : {}) } });
      }
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
      const root = await rootFromPath(await leafOf(kind, subject), b.index, b.size, b.path.map(hex.decode));
      if (!equal(root, hex.decode(b.root))) throw new Error("the inclusion path does not lead to the batch root");
      batchRoot = root;
      add({ id: "batch", state: "pass", title: "Included in batch", detail: `Entry ${b.index + 1} of ${b.size} in batch ${b.id}.`, facts: { batch: b.id, root: b.root } });
    } catch (e) {
      add({ id: "batch", state: "fail", title: "Batch inclusion", detail: msg(e) });
    }
  }

  // 4. OpenTimestamps → Bitcoin block header.
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
        let best: { height: number; time: number; sources: string[] } | undefined;
        const errors: string[] = [];
        for (const a of btc) {
          const height = (a.att as { height: number }).height;
          try {
            const { value: block, sources } = await consensus(explorers("bitcoin"), (base) => blockAt(base, height, f), (bl) => bl.merkleRoot);
            if (!merkleRootMatches(a.msg, block.merkleRoot)) throw new Error(`does not match block ${height}'s merkle root`);
            if (!best || block.time < best.time) best = { height, time: block.time, sources };
          } catch (e) { errors.push(`block ${height}: ${msg(e)}`); }
        }
        if (!best) throw new Error(errors.join("; "));
        seen(best.time);
        add({ id: "ots", state: "pass", title: "Timestamped on Bitcoin", detail: `Committed in Bitcoin block ${best.height} (${new Date(best.time * 1000).toISOString()}) via OpenTimestamps.`,
          facts: { height: best.height, time: best.time, explorers: best.sources.length } });
      }
    } catch (e) {
      add({ id: "ots", state: "fail", title: "OpenTimestamps", detail: msg(e) });
    }
  }

  // 5. HardState Anchor: the daily OP_RETURN.
  if (!proof.anchor) {
    add({ id: "anchor", state: batchRoot ? "pending" : "skip", title: "HardState Anchor", detail: "Batches are also written to Bitcoin in HardState's own daily transaction." });
  } else if (batchRoot) {
    const a = proof.anchor;
    try {
      const root = await rootFromPath(await leafOf("batch", batchRoot), a.index, a.size, a.path.map(hex.decode));
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
          facts: { txid: a.txid, network: a.network, height: tx.blockHeight ?? 0, time: tx.blockTime ?? 0, explorers: sources.length } });
      }
    } catch (e) {
      add({ id: "anchor", state: "fail", title: "HardState Anchor", detail: msg(e) });
    }
  }

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
  if (opts.log && proof.subject.kind === "event") {
    const ev = proof.subject.signed.event;
    const r = await replay(opts.log);
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

  // A session key stolen after it expired could still sign back-dated events; Bitcoin bounds when the event existed,
  // so a session event first proven long after the session ended is refused.
  if (sessionExpires && provenBefore !== undefined && provenBefore * 1000 > Date.parse(sessionExpires) + SESSION_ANCHOR_GRACE_MS) {
    const sigStep = steps.find((s) => s.id === "signature");
    if (sigStep) Object.assign(sigStep, { state: "fail", title: "Signed with an expired session",
      detail: `The session expired ${sessionExpires}, but this record was first proven on Bitcoin at ${new Date(provenBefore * 1000).toISOString()}.` });
  }

  const failed = steps.some((s) => s.state === "fail");
  const onChain = steps.some((s) => (s.id === "ots" || (s.id === "anchor" && proof.anchor?.network === "bitcoin")) && s.state === "pass");
  return { status: failed ? "invalid" : onChain ? "valid" : "pending", steps, provenBefore, subjectHash: hex.encode(subject) };
}
