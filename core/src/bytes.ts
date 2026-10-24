// bytes.ts — the byte helpers everything else uses. WebCrypto and TextEncoder only, so the same code runs in Workers,
// browsers and Node.

export type Bytes = Uint8Array<ArrayBuffer>;

export const utf8 = (s: string): Bytes => Uint8Array.from(new TextEncoder().encode(s));

export const hex = {
  encode: (b: Bytes) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join(""),
  decode: (h: string): Bytes => {
    const s = h.replace(/^0x/, "");
    if (s.length % 2 || /[^0-9a-f]/i.test(s)) throw new Error(`not hex: ${h.slice(0, 16)}…`);
    return Uint8Array.from(s.match(/../g) ?? [], (x) => parseInt(x, 16));
  },
};

export const b64url = {
  encode: (b: Bytes) => {
    let s = "";
    for (let i = 0; i < b.length; i += 0x8000) s += String.fromCharCode(...b.subarray(i, i + 0x8000));
    return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  },
  decode: (s: string): Bytes =>
    Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4)), (c) => c.charCodeAt(0)),
};

export const b64 = {
  encode: (b: Bytes) => { const s = b64url.encode(b); return s.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (s.length % 4)) % 4); },
  decode: (s: string) => b64url.decode(s.replace(/=+$/, "")),
};

export function concat(...xs: Bytes[]): Bytes {
  const o = new Uint8Array(xs.reduce((n, x) => n + x.length, 0));
  let i = 0;
  for (const x of xs) { o.set(x, i); i += x.length; }
  return o;
}

export const equal = (a: Bytes, b: Bytes) => a.length === b.length && a.every((x, i) => x === b[i]);

/** Lexicographic byte order, the tie-break OpenTimestamps uses to sort ops and attestations. */
export function compare(a: Bytes, b: Bytes): number {
  for (let i = 0; i < Math.min(a.length, b.length); i++) if (a[i] !== b[i]) return a[i] - b[i];
  return a.length - b.length;
}

export const sha256 = async (b: Bytes): Promise<Bytes> => new Uint8Array(await crypto.subtle.digest("SHA-256", b));

export const randomBytes = (n: number): Bytes => crypto.getRandomValues(new Uint8Array(n));

export const reverse = (b: Bytes): Bytes => Uint8Array.from(b).reverse();
