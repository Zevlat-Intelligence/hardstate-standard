// client.ts — a small SDK for the HardState API: append signed events (rebuilding on a moved head), stamp hashes, fetch
// proofs and logs, and verify. The signer is a callback, so the same client drives a browser passkey, an Ed25519 key
// on a server, or a test key.

import type { Bytes } from "./bytes.ts";
import type { DocRef, HssEvent, Signature, SignedEvent } from "./event.ts";
import { operatorHash, operatorRequest, type OperatorOp } from "./operator.ts";
import type { HardStateProof, ProofStatus } from "./proof.ts";
import { verifyProof, type Verdict, type VerifyOptions } from "./verify.ts";

export const DEFAULT_API = "https://api.hardstate.net";

/** What the caller decides; the client fills in hss, seq, prev and (by default) ts from the live head. */
export type EventDraft = Omit<HssEvent, "hss" | "seq" | "prev" | "ts" | "docs"> & { ts?: string; docs?: DocRef[] };

export interface AppendResult { hash: string; issuer: string; seq: number; status: ProofStatus; proof: string; receipt: string }
export interface ProofResponse {
  proof: HardStateProof; status: ProofStatus; receipt?: string;
  batch?: { id: string; otsStatus: string; otsHeight: number | null; otsTime: number | null };
  anchor?: { id: string; network: string; txid: string; status: string; height: number | null; blockTime: number | null };
}

export class HardStateError extends Error {
  status: number;
  body: Record<string, unknown>;
  constructor(status: number, body: Record<string, unknown>) {
    super(String(body.error ?? `HTTP ${status}`));
    this.status = status;
    this.body = body;
  }
}

export class HardStateClient {
  api: string;
  private f: typeof fetch;

  constructor(api = DEFAULT_API, f: typeof fetch = (...a) => fetch(...a)) {
    this.api = api.replace(/\/$/, "");
    this.f = f;
  }

  async request<T>(path: string, init?: RequestInit): Promise<T> {
    const res = await this.f(`${this.api}${path}`, { ...init, headers: { "content-type": "application/json", ...init?.headers } });
    const body = res.headers.get("content-type")?.includes("json") ? await res.json() : { error: await res.text() };
    if (!res.ok) throw new HardStateError(res.status, body as Record<string, unknown>);
    return body as T;
  }

  /** The issuer's log head, or null if the issuer does not exist yet. */
  async head(issuer: string): Promise<{ seq: number; hash: string } | null> {
    try { return (await this.request<{ head: { seq: number; hash: string } }>(`/v1/issuers/${issuer}`)).head; } catch (e) {
      if (e instanceof HardStateError && e.status === 404) return null;
      throw e;
    }
  }

  /** Builds the next event on the live head, has `sign` sign it, and submits. Rebuilds and re-signs if the head moved. */
  async append(draft: EventDraft, sign: (e: HssEvent) => Promise<Signature>, opts: { publish?: { commitment: string; digest: string; salt: string }[]; retries?: number } = {}) {
    for (let attempt = 0; ; attempt++) {
      const head = await this.head(draft.issuer);
      const event: HssEvent = {
        hss: 1, ...draft, docs: draft.docs ?? [], ts: draft.ts ?? new Date().toISOString(),
        seq: head ? head.seq + 1 : 0, prev: head ? head.hash : null,
      };
      try {
        const sig = await sign(event);
        const r = await this.request<AppendResult>("/v1/events", { method: "POST", body: JSON.stringify({ event, sig, publish: opts.publish }) });
        return { ...r, event, sig };
      } catch (e) {
        if (e instanceof HardStateError && e.status === 409 && attempt < (opts.retries ?? 2)) continue;
        throw e;
      }
    }
  }

  /** Signs an operator request (operator.ts) with `sign` over its hash and posts it to `path`. */
  async operator<T>(path: string, op: OperatorOp, issuer: string, key: string, sign: (hash: Bytes) => Promise<Signature>, params?: Record<string, unknown>): Promise<T> {
    const request = operatorRequest(op, issuer, key, params);
    const sig = await sign(await operatorHash(request));
    return this.request<T>(path, { method: "POST", body: JSON.stringify({ request, sig }) });
  }

  stamp(digest: string) {
    return this.request<{ hash: string; status: ProofStatus; proof: string; verify: string }>("/v1/stamp", { method: "POST", body: JSON.stringify({ digest }) });
  }

  proof(hash: string) { return this.request<ProofResponse>(`/v1/proofs/${hash}`); }

  /** The whole log, following pagination. */
  async log(issuer: string): Promise<SignedEvent[]> {
    const out: SignedEvent[] = [];
    let from: number | null = 0;
    while (from !== null) {
      const page: { events: SignedEvent[]; next: number | null } = await this.request(`/v1/issuers/${issuer}/log?from=${from}&limit=5000`);
      out.push(...page.events);
      from = page.next;
    }
    return out;
  }

  /** Fetches the proof (and the issuer's full log, for events) and verifies it locally against Bitcoin. */
  async verify(hash: string, opts: Omit<VerifyOptions, "log"> & { withLog?: boolean } = {}): Promise<Verdict & { response: ProofResponse }> {
    const response = await this.proof(hash);
    const s = response.proof.subject;
    const log = s.kind === "event" && opts.withLog !== false ? await this.log(s.signed.event.issuer) : undefined;
    return { ...(await verifyProof(response.proof, { ...opts, log })), response };
  }
}

