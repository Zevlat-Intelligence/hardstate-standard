// canonical.ts — JSON Canonicalization Scheme (RFC 8785). An event is hashed over these bytes, so two parties that
// hold the same object always agree on its hash, whatever order their JSON library wrote the keys in.
//
// ECMAScript's JSON.stringify already serializes numbers and strings the way RFC 8785 asks; what it does not do is sort
// object keys (by UTF-16 code units) or refuse values JSON cannot carry. That is all this adds.

export type Json = null | boolean | number | string | Json[] | { [k: string]: Json };

export function canonicalize(value: unknown): string {
  if (value === null || typeof value === "boolean" || typeof value === "string") return JSON.stringify(value);
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error("JCS: non-finite number");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map((v) => canonicalize(v === undefined ? null : v)).join(",")}]`;
  if (typeof value === "object") {
    const o = value as Record<string, unknown>;
    // Default sort compares UTF-16 code units, which is exactly RFC 8785's order.
    const keys = Object.keys(o).filter((k) => o[k] !== undefined).sort();
    return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalize(o[k])}`).join(",")}}`;
  }
  throw new Error(`JCS: cannot serialize ${typeof value}`);
}
