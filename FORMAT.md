# HardState Receipt Format (HRF-1)

**Status:** v1.3 · **Date:** 2026-11-17 · **License:** CC BY-ND 4.0 (this text); the verifier is Apache-2.0

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

- Leaf data is a kind byte followed by the item: `0x01 ‖ record_hash`, `0x02 ‖ digest` (a bare SHA-256 stamp),
  `0x03 ‖ batch_root` (in an anchor tree), `0x04 ‖ d` (an institution's index, §9) or `0x05 ‖ lo ‖ hi` (an index gap,
  §9), `0x06 ‖ record_hash` (an entry of an institution's log, §11) or `0x07 ‖ d` (a witnessed checkpoint, §13).
- Tree: RFC 9162 Merkle Tree Hash, with `leaf = SHA-256(0x00 ‖ data)` and `node = SHA-256(0x01 ‖ left ‖ right)`.
- Inclusion: a **sided path**, bottom-up. Each step `{ "s": "L" | "R", "h": "<hex>" }` is a sibling hash and the side
  it sits on (`L`: `node = SHA-256(0x01 ‖ h ‖ running)`; `R`: `node = SHA-256(0x01 ‖ running ‖ h)`). Folding from
  the leaf must yield the root. The path names no leaf position and no tree size.
- Proofs issued before 2026-11-17 carry RFC 9162 audit paths instead (`index`, `size` and `path` as plain hex
  hashes). Verifiers MUST still accept them.

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
  "batch":  { "id": "…", "closedAt": "…", "root": "…", "path": [{ "s": "R", "h": "…" }, { "s": "L", "h": "…" }] },
  "ots":    "<base64 detached .ots for batch.root>",
  "anchor": { "network": "bitcoin" | "signet", "txid": "…", "root": "…", "path": [{ "s": "L", "h": "…" }] },
  "issuedAt": "…"
}
```

`batch`, `ots` and `anchor` are absent until they exist. Fetching the proof again later completes it.

## 8. Verification

1. **Integrity.** `SHA-256(canonical(subject.signed.event)) == subject.hash`.
2. **Signature.** The key named by `actor` is declared by a record in `authority` at a `seq` no later than the
   record's, and the signature verifies under that key (§3).
3. **Batch.** The leaf (`0x01 ‖ hash` or `0x02 ‖ digest`) folded up `batch.path` yields `batch.root`.
4. **OpenTimestamps.** For each Bitcoin attestation at height `h`, the attested message equals the merkle root of
   block `h`. The block MUST be read from at least two independent sources that agree.
5. **Anchor.** `0x03 ‖ batch.root` folded up `anchor.path` yields `anchor.root`, and transaction `anchor.txid` is confirmed
   and carries the §6 script for it. The same two-source rule applies.
6. **Document** (optional). Given a file and its salt, the recomputed commitment is one of `event.docs`.

**Verdict:** *invalid* if any step that ran fails; *valid* if steps 1–3 pass and at least one of 4 or 5 passes on
Bitcoin mainnet; *pending* otherwise. The earliest confirmed block time is reported as "existed before".

The HardState Verifier (https://app.hardstate.net/verify) also evaluates the institution's own authority rules and the
completeness of its log.

## 9. Proof of Absence (`hardstate: "absence"`)

A Proof of Absence shows that, as of a given entry of an institution's log, the log held **no** record of one kind
about one id. The kinds are `review` (a human review of an AI decision; id: the decision's hash), `revoke` (a
revocation of a key or the closing of a session; id: the key id) and `doc` (the record of a document; id: its
commitment).

- **Key:** `key = SHA-256("hardstate/index/v1" ‖ kind ‖ 0x00 ‖ id)`, with kind and id as UTF-8.
- **Gaps:** the index is a sorted set of keys closed by `LOW = 0x00…00` and `HIGH = 0xff…ff` (32 bytes each). Each
  leaf is the gap between two neighbouring bounds, with leaf data `0x05 ‖ lo ‖ hi` (§5 hashing). The index root is
  the tree over those leaves in ascending order.
- **Index leaf:** the index root enters a batch as a leaf with data `0x04 ‖ d`, where
  `d = SHA-256("hardstate/index-root/v1" ‖ issuer ‖ 0x00 ‖ uint64be(asOf.seq) ‖ asOf.hash ‖ indexRoot)`.

```json
{
  "hardstate": "absence", "hss": 1, "issuer": "…",
  "asOf":  { "seq": 812, "hash": "…" },
  "query": { "kind": "review" | "revoke" | "doc", "id": "…" },
  "gap":   { "lo": "…", "hi": "…", "path": [{ "s": "R", "h": "…" }] },
  "index": { "root": "…" },
  "batch": { "id": "…", "closedAt": "…", "root": "…", "path": [{ "s": "L", "h": "…" }] },
  "ots": "…", "anchor": { … }, "issuedAt": "…"
}
```

**Verification:**
1. `lo < key < hi`, compared as unsigned bytes. A key equal to a bound is present, not absent.
2. The gap leaf, folded up `gap.path`, yields `index.root`.
3. The index leaf (`0x04 ‖ d`), folded up `batch.path`, yields `batch.root`.
4. The batch is on Bitcoin, through OpenTimestamps or the HardState Anchor, exactly as in §8 steps 4–5.

**Verdict:** *valid* when steps 1–3 pass and the batch is confirmed on Bitcoin mainnet; *pending* while it is not yet;
*invalid* otherwise. The reading is: "as of entry `asOf.seq`, anchored before block X, there was no such record". Anyone
holding the institution's full log up to `asOf.seq` can rebuild the index and compare roots.

## 10. Process heartbeats (`ai.heartbeat`)

A process that records (an AI system, for instance) signs a heartbeat at a regular interval. Its `public` carries
`every` (seconds), `decisions`, `runs` and `failures` (its own records since its previous beat), `since` (the `seq` of
that previous beat), `instance` (an id for the running process) and `digest`:

```
acc_0 = 0x00…00 (32 bytes)
acc_i = SHA-256("hardstate/ai-stream/v1" ‖ acc_(i-1) ‖ record_hash_i)
digest = hex(acc_n)
```

over the hashes of that process's records (same `actor` and `instance`, heartbeats excluded) since its previous beat, in
`seq` order.

**Window verification:** given two heartbeats `p` and `b` and every log entry strictly between them:
1. Both are `ai.heartbeat` events of the same issuer, `actor` and `instance`, and `b.public.since == p.seq`.
2. The entries are exactly `p.seq + 1 … b.seq - 1`, each one's `prev` is the hash of the one before it, starting at
   `p` and ending with `b.prev`. Otherwise the window is *unlinked*.
3. The counts and the recomputed `digest` over that process's records match `b`'s. Otherwise a record is *missing*.
4. `b.ts - p.ts ≤ 2 × every`. Otherwise there is a *gap*: the logging stopped in between.

If all four hold, the window is *complete*: the log holds exactly the records the process vouched for.

## 11. Log checkpoints (`hardstate: "checkpoint"`)

An institution's log can also be read as a **Merkle Mountain Range** over its entries in `seq` order:

- Leaf data is `0x06 ‖ record_hash`, so `leaf = SHA-256(0x00 ‖ 0x06 ‖ record_hash)`. Nodes are hashed as in §5.
- The forest has one perfect tree per set bit of the size `n`, highest first. Positions alone define it, never time.
- The **root** bags the peaks from the right: `root = node(p₁, node(p₂, … node(pₖ₋₁, pₖ)))`. That is exactly the §5
  tree root over the same leaves. The root of an empty log is `SHA-256("")`.

A **checkpoint** states the log at one size:

```json
{ "checkpoint": { "hardstate": "checkpoint", "v": 1, "issuer": "…", "size": 29, "root": "<hex>",
                  "head": { "seq": 28, "hash": "<hex>" }, "ts": "…", "signer": "<key id>" },
  "sigs": [{ "key": "<key id>", "sig": { "kind": "ed25519", "signature": "…" } }] }
```

Each signature is over `SHA-256("hardstate/checkpoint/v1" ‖ canonical(checkpoint))`. The operator signs first, with
its published key. Independent witnesses add signatures over the same hash.

- **Checkpoint.** `size == head.seq + 1`, and the operator's signature verifies under its published key.
- **Inclusion.** A record is in the log at a checkpoint when `leaf(record_hash)`, folded up a sided path (§5), yields
  `root`.
- **Consistency.** A checkpoint of size `n` extends one of size `m ≤ n` when the proof `{ from: m, to: n, peaks,
  blocks }` checks:
  1. `peaks` are the hashes of the size-`m` peaks (highest first), and they bag to the old root.
  2. `blocks` are the hashes of the perfect subtrees that cover positions `m … n−1`, in order. At each position `p`,
     take the largest `2^l` with `p mod 2^l = 0` and `p + 2^l ≤ n`.
  3. Pushing each block onto the old peaks, and merging the last two trees while they have the same height
     (`node(left, right)`), yields peaks that bag to the new root.
- **Verdict.** A receipt whose record is included in a checkpoint the operator signed was in the log, unchanged,
  at that size. A pair of checkpoints with a valid consistency proof shows that nothing before the first one was
  removed, reordered or rewritten.

## 12. Witnesses

Other institutions witness a log's checkpoints (§11). A witness signs only after checking that the new checkpoint
extends the last one it signed for that log (a consistency proof). It signs outside every log: no log ever carries
another log's hash.

- **Witness key:** an Ed25519 `system` key the witnessing institution declares in its own log, scoped to exactly
  `["witness.cosign"]`. It never signs a log record.
- **Cosignature:** `{ witness, key, sig, ts }`, where `sig` is the signature over
  `SHA-256("hardstate/witness/v1" ‖ canonical({ issuer, size, root }))` of the checkpoint.
- **Choice of witnesses:** for a checkpoint of `issuer`, with Bitcoin block hash `B` (the latest confirmed block the
  operator knew), each candidate institution `w ≠ issuer` gets the score
  `SHA-256(SHA-256("hardstate/witness-select/v1" ‖ B ‖ issuer) ‖ w)`. The `k` lowest scores are the witnesses. Anyone
  can recompute the choice from `B`.

A verifier MUST check, for each cosignature it counts:

1. the key is the witness institution's live witness key;
2. the witness is not the checkpoint's own institution;
3. the signature verifies over the witness hash of this checkpoint;
4. when a choice is given, the witness is one of the `k` the block chose.

The checkpoint is **witnessed** when at least `k` distinct institutions pass.

**Equivocation:** two checkpoints of the same `issuer` and `size` that differ in `root` or `head`, each signed by the
same key (the operator's over the checkpoint hash, or a witness's over the witness hash), prove that the log was shown
in two versions. A verifier checks both signatures and that the two checkpoints differ.

## 13. Layered receipts (`checkpoint` section)

On the layered log, a batch holds one leaf per witnessed checkpoint instead of one leaf per record:

- **Checkpoint leaf:** kind `0x07`, with data
  `SHA-256("hardstate/checkpoint-leaf/v1" ‖ checkpoint_hash ‖ cosig_set_hash)`, where `checkpoint_hash` is the §11
  hash and `cosig_set_hash = SHA-256("hardstate/cosigs/v1" ‖ canonical(cosigs))` over the cosignatures sorted by
  `witness`, then `key`. The leaf seals the checkpoint together with the exact cosignatures it had when it was batched.

Such a receipt carries a `checkpoint` section in place of `batch`:

```json
"checkpoint": {
  "signed":  { "checkpoint": { … §11 … }, "sigs": [ … ] },
  "cosigs":  [ { "witness": "…", "key": "…", "sig": { … }, "ts": "…" } ],
  "witnessKeys": [ { "issuer": "…", "info": { …key object… } } ],
  "witnesses": { "height": 900000, "blockHash": "…", "selected": ["…", "…"] },
  "path":  [ { "s": "L", "h": "…" } ],
  "batch": { "id": "…", "closedAt": "…", "root": "…", "path": [ { "s": "R", "h": "…" } ] }
}
```

`ots` and `anchor` are then those of the checkpoint's batch. A verifier replaces step 3 of §8 with:

1. The checkpoint is of the record's institution, and `leaf(record_hash)` (§11, kind `0x06`) folded up `path` yields
   the checkpoint's `root`.
2. With the operator's published key, the operator's signature on the checkpoint verifies (§11).
3. With `witnessKeys`, every cosignature verifies as in §12 (only institutions in `witnesses.selected` count, when
   given). The receipt names the institutions that witnessed it.
4. The checkpoint leaf, folded up `batch.path`, yields `batch.root`.

Steps 4–6 of §8 then apply to `batch.root`. The verdict rules are unchanged. A receipt without a `checkpoint` section
is checked as in §8.

## 14. Limits

A receipt proves that an institution's key signed a record before a Bitcoin block. It does not prove that the content
is true. Only hashes reach Bitcoin; `public` holds whatever the institution chose to publish.
