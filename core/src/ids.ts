// ids.ts — what the public sees of the people who sign: a short code per key and a salted commitment to who holds it.
// HardState exposes institutions and their procedures, not their officials. A key's public face is its code
// ("D12SX3"), its title (the label: "Building inspector") and its department; the holder's name stays with the
// institution. The commitment lets the institution prove, when an auditor or a court asks, who held a key: it reveals
// the name and the salt, and anyone recomputes the commitment the log has carried since the key was added.

import { concat, hex, randomBytes, sha256, utf8, type Bytes } from "./bytes.ts";

/** Crockford's base32: no I, L, O or U, so a code read aloud or copied by hand survives. */
const CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
export const KEY_CODE_LENGTH = 6;
const CODE_DOMAIN = utf8("hardstate/key-code/v1");
const HOLDER_DOMAIN = utf8("hardstate/holder/v1");

/** The 6-character code of a key within its institution: base32 of sha256(domain ‖ issuer ‖ 0x00 ‖ key id). Anyone can
 * compute it; the log keeps codes unique per institution (log.ts). */
export async function keyCode(issuer: string, keyId: string): Promise<string> {
  const h = await sha256(concat(CODE_DOMAIN, utf8(issuer), new Uint8Array([0]), utf8(keyId)));
  let bits = 0, acc = 0, out = "";
  for (const byte of h) {
    acc = (acc << 8) | byte;
    bits += 8;
    while (bits >= 5 && out.length < KEY_CODE_LENGTH) { out += CROCKFORD[(acc >> (bits - 5)) & 31]; bits -= 5; }
    if (out.length === KEY_CODE_LENGTH) break;
    acc &= (1 << bits) - 1;
  }
  return out;
}

/** "d12-sx3", " D12SX3 " → "D12SX3"; anything that cannot be a code → null. Crockford reads O as 0 and I/L as 1. */
export function normalizeKeyCode(s: string): string | null {
  const c = s.trim().toUpperCase().replace(/[\s-]/g, "").replace(/O/g, "0").replace(/[IL]/g, "1");
  return c.length === KEY_CODE_LENGTH && [...c].every((x) => CROCKFORD.includes(x)) ? c : null;
}

/** A holder's name as committed: Unicode NFC, trimmed, inner whitespace collapsed. */
export const normalizeHolder = (name: string) => name.normalize("NFC").trim().replace(/\s+/g, " ");

/** hex sha256("hardstate/holder/v1" ‖ salt ‖ utf8(name)), the `holder` a person key carries (HSS-1 §5.1). */
export async function holderCommitment(name: string, salt: Bytes): Promise<string> {
  return hex.encode(await sha256(concat(HOLDER_DOMAIN, salt, utf8(normalizeHolder(name)))));
}

/** A fresh salt and the commitment for `name`: the salt goes to the institution's private directory, never the log. */
export async function commitHolder(name: string): Promise<{ salt: string; holder: string }> {
  const salt = randomBytes(16);
  return { salt: hex.encode(salt), holder: await holderCommitment(name, salt) };
}
