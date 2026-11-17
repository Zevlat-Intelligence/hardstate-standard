# HardState Receipt Format (HRF-1)

**Status:** v1 · **Date:** 2026-11-17 · **License:** CC BY-ND 4.0 (this text); the verifier is Apache-2.0

A HardState Receipt proves four things about one record, to anyone, without trusting the institution that wrote it or
HardState: the record is **intact**, it was **signed** by the key it names, it is **included** in a batch, and that batch
existed **before a Bitcoin block**. This document defines the bytes a verifier checks. The reference verifier is
[`@hardstate/receipt`](receipt/). Its checks are the ones https://app.hardstate.net/verify runs in your browser.

The key words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119.

## 1. Encoding

- Hash function: SHA-256. Hashes are written as lowercase hex (64 characters).
- Binary in JSON (signatures, keys, WebAuthn data): base64url without padding.
- Canonical JSON: **RFC 8785 (JCS)**. In this document, `canonical(x)` is the UTF-8 bytes of the JCS serialization of x.
- Times: ISO 8601 / RFC 3339 strings in UTC.

## 2. Record

```json
{
  "hss": 1, "issuer": "<slug>", "seq": 5, "prev": "<hex>", "type": "case.inspect", "case": "BP-2026-4077",
  "ts": "2026-10-20T15:18:39.120Z", "public": { … }, "docs": [{ "label": "…", "commitment": "<hex>" }],
  "actor": "<key id>"
}
```

`record_hash = SHA-256(canonical(record))`. The signature is not part of the record. `public` is published as-is.

## 3. Signature

```json
{ "event": { …record… }, "sig": { "kind": "passkey" | "ed25519", … } }
```

The signing key is a key object `{ id, kind, alg, publicKey, rpId?, label, role }`, where `publicKey` is the SPKI DER
in base64url. Ed25519 key ids are `"ed25519:" + hex(SHA-256(spki)[0..16])`; passkey ids are WebAuthn credential ids.

- **`ed25519`:** `sig.signature` is the Ed25519 signature over the 32 raw bytes of `record_hash`.
- **`passkey`:** a WebAuthn assertion (`authenticatorData`, `clientDataJSON`, `signature`) made with
  `challenge = record_hash`. The verifier MUST check all of the following:
  - `type == "webauthn.get"`;
  - `challenge == base64url(record_hash)`;
  - `origin` is `https://<rpId>` or a subdomain of it;
  - `crossOrigin` is not `true`;
  - `authenticatorData[0..32] == SHA-256(rpId)`, with the user-presence flag set;
  - the signature over `authenticatorData ‖ SHA-256(clientDataJSON)` verifies (ES256 with a DER signature, RS256, or
    EdDSA).

## 4. Documents

A record commits to each document. The document itself is never in the record:

```
commitment = SHA-256( "hardstate/doc/v1" ‖ salt ‖ SHA-256(file) )      salt: 32 bytes
```

The salt travels with the receipt, in the URL fragment (`#k=…`), which browsers never send to a server. Anyone holding
the file and the salt can check that the file is the one recorded.

## 5. Batch

- Leaf data is a kind byte followed by 32 bytes: `0x01 ‖ record_hash`, `0x02 ‖ digest` (a bare SHA-256 stamp), or
  `0x03 ‖ batch_root` (in an anchor tree).
- Tree: RFC 9162 Merkle Tree Hash, with `leaf = SHA-256(0x00 ‖ data)` and `node = SHA-256(0x01 ‖ left ‖ right)`.

## 6. Bitcoin

- **OpenTimestamps:** a standard detached `.ots` file over the batch root. `ots verify -d <root> <file>.ots` works without
  any HardState code.
- **HardState Anchor:** a transaction output `OP_RETURN PUSH36("HSS" ‖ 0x01 ‖ root32)` (script `6a2448535301` followed by the 32 bytes)
  whose root is an anchor tree (§5, leaves `0x03`) over batch roots.

## 7. Proof file (`.hardstate.json`)

```json
{
  "hardstate": "proof", "hss": 1,
  "subject": { "kind": "event", "signed": { "event": {…}, "sig": {…} }, "hash": "…" } | { "kind": "stamp", "digest": "…" },
  "authority": [ /* signed records that declare the signer's key in their public.key, ascending seq */ ],
  "batch":  { "id": "…", "closedAt": "…", "root": "…", "size": 8, "index": 5, "path": ["…"] },
  "ots":    "<base64 detached .ots for batch.root>",
  "anchor": { "network": "bitcoin" | "signet", "txid": "…", "root": "…", "size": 1, "index": 0, "path": [] },
  "issuedAt": "…"
}
```

`batch`, `ots` and `anchor` are absent until they exist. Fetching the proof again later completes it.

## 8. Verification

1. **Integrity.** `SHA-256(canonical(subject.signed.event)) == subject.hash`.
2. **Signature.** The key named by `actor` is declared by a record in `authority` at a `seq` no later than the
   record's, and the signature verifies under that key (§3).
3. **Batch.** The leaf (`0x01 ‖ hash` or `0x02 ‖ digest`) with `batch.path` yields `batch.root`.
4. **OpenTimestamps.** For each Bitcoin attestation at height `h`, the attested message equals the merkle root of
   block `h`. The block MUST be read from at least two independent sources that agree.
5. **Anchor.** `0x03 ‖ batch.root` with `anchor.path` yields `anchor.root`, and transaction `anchor.txid` is confirmed
   and carries the §6 script for it. The same two-source rule applies.
6. **Document** (optional). Given a file and its salt, the recomputed commitment is one of `event.docs`.

**Verdict:** *invalid* if any step that ran fails; *valid* if steps 1–3 pass and at least one of 4 or 5 passes on
Bitcoin mainnet; *pending* otherwise. The earliest confirmed block time is reported as "existed before".

The HardState Verifier (https://app.hardstate.net/verify) also evaluates the institution's own authority rules and the
completeness of its log.

## 9. Limits

A receipt proves that an institution's key signed a record before a Bitcoin block. It does not prove that the content
is true. Only hashes reach Bitcoin; `public` holds whatever the institution chose to publish.
