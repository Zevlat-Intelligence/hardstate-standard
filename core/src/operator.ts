// operator.ts — signed requests to a HardState operator (billing, paid express anchors). They are not part of HSS-1 and
// never enter a HardState Log: they are how an institution's admin tells the operator running its node what to do with
// the account, authorized the same way as everything else, by a signature from a key the institution's log authorizes.
//
// The signed bytes are domain-separated ("hardstate/operator/v1" ‖ JCS(request)), so a signature over a request can
// never pass as a signature over an event (whose hash is sha256 of bare JCS) or the other way round.

import { b64url, concat, randomBytes, sha256, utf8, type Bytes } from "./bytes.ts";
import { canonicalize } from "./canonical.ts";
import type { Signature } from "./event.ts";

const OPERATOR_DOMAIN = utf8("hardstate/operator/v1");

/** How far a request's `ts` may be from the operator's clock. */
export const OPERATOR_SKEW_MS = 5 * 60_000;

export type OperatorOp = "billing.checkout" | "billing.invoice" | "billing.portal" | "anchor.express" | "directory.read" | "directory.write";

export interface OperatorRequest {
  op: OperatorOp;
  issuer: string;
  /** Id of the signing key, live in `issuer`'s log: an institution admin's for billing and anchors; for the private
   * directory, any person of the institution (or a session they opened) to read it, an admin over the key to write. */
  key: string;
  /** ISO 8601, within OPERATOR_SKEW_MS of the operator's clock. */
  ts: string;
  /** 16 random bytes, base64url: each request is accepted once. */
  nonce: string;
  params?: Record<string, unknown>;
}

export interface SignedOperatorRequest { request: OperatorRequest; sig: Signature }

export const operatorHash = async (r: OperatorRequest): Promise<Bytes> => sha256(concat(OPERATOR_DOMAIN, utf8(canonicalize(r))));

/** A fresh request for `op`, stamped now with a random nonce. */
export function operatorRequest(op: OperatorOp, issuer: string, key: string, params?: Record<string, unknown>): OperatorRequest {
  return { op, issuer, key, ts: new Date().toISOString(), nonce: b64url.encode(randomBytes(16)), ...(params ? { params } : {}) };
}
