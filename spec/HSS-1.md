# HardState Standard HSS-1 (v0.3, draft)

**Status:** draft for public comment · **Date:** 2026-10-22 · **v0.2:** delegated sessions, scoped system keys · **v0.3:** departments, key codes, private holders · **License:** CC BY-ND 4.0 (text), Apache-2.0 (reference implementation)

HSS-1 defines how an institution keeps a public, append-only, signed record of what it does, and how anyone can verify
that record against Bitcoin without trusting the institution or any operator. The reference implementation is
[`@hardstate/core`](https://github.com/Zevlat-Intelligence/hardstate-standard/tree/main/core); where this text and the
code disagree, file an issue: the text is meant to win.

The key words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119.

---

## 1. Model in one paragraph

An **issuer** (a ministry, a municipality, a university, an NGO) keeps one **HardState Log**: a hash chain of signed
**events**. Each event records one act ("case opened", "inspection passed", "permit approved"), names the key that
signed it, commits to any documents by salted hash, and points to the previous event. Operators collect events from
many issuers into **batches** (Merkle trees), commit each batch root to Bitcoin through **OpenTimestamps**, and once a
day write a tree of batch roots to Bitcoin directly in a **HardState Anchor** transaction. A **HardState Proof** bundles
everything needed to check one event offline. A **verifier** recomputes every link from the event bytes to a Bitcoin
block header.

What this gives: (1) **integrity**: an anchored event cannot be altered; (2) **attribution**: it was signed by a key
the issuer's own log authorized at that point; (3) **completeness**: no anchored event can be removed or reordered
without breaking the chain; (4) **time**: it existed before a specific Bitcoin block.
What it does not give: truth of the content, or proof that an unrecorded act did not happen (see §9).

## 2. Encoding

- Hash function: SHA-256. Hashes are written as lowercase hex (64 characters).
- Binary in JSON (signatures, keys, WebAuthn data): base64url without padding.
- Canonical JSON: **RFC 8785 (JCS)**. `canonical(x)` below means the UTF-8 bytes of the JCS serialization.
- Times: ISO 8601 / RFC 3339 strings in UTC (`2026-10-20T15:18:38.955Z`).

## 3. Events

### 3.1 Structure

```json
{
  "hss": 1,
  "issuer": "esperanza-demo",
  "seq": 5,
  "prev": "09f54f6f…69b9ab",
  "type": "case.inspect",
  "case": "BP-2026-4077",
  "ts": "2026-10-20T15:18:39.120Z",
  "public": { "result": "pass", "inspector": "Unit 3" },
  "docs": [{ "label": "Inspection report", "commitment": "…", "mime": "application/pdf", "size": 812 }],
  "actor": "ed25519:4be1…"
}
```

| Field | Rule |
|---|---|
| `hss` | MUST be `1`. |
| `issuer` | Lowercase slug `^[a-z0-9][a-z0-9-]{1,62}[a-z0-9]$`. Stable for the life of the log. |
| `seq` | `0` for the first event, then exactly previous `seq + 1`. |
| `prev` | `null` at `seq 0`; otherwise the event hash (§3.2) of the event at `seq - 1`. |
| `type` | Dotted lowercase `domain.action` (`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$`). The domains `issuer`, `key`, `session` and `dept` are reserved for §5. |
| `case` | OPTIONAL. Up to 128 characters. Groups the events of one procedure. |
| `ts` | When the issuer states the act happened. Untrusted; the Bitcoin anchor bounds it from above. |
| `public` | JSON object. **Published as-is.** Transparency by default: anything here is public. |
| `docs` | Array of document references (§4). MAY be empty. |
| `actor` | Key id (§5.1) of the signer. |

A serialized event MUST NOT exceed 64 KiB. Unknown top-level fields MUST be rejected in `hss: 1`.

### 3.2 Event hash

`event_hash = SHA-256(canonical(event))`. The signature is not part of the event.

### 3.3 Signed event

```json
{ "event": { … }, "sig": { "kind": "passkey" | "ed25519", … } }
```

- **`ed25519`** (system-to-system integrations): `sig.signature` is the Ed25519 signature over the 32 raw bytes of
  `event_hash`.
- **`passkey`** (people): a WebAuthn assertion (`authenticatorData`, `clientDataJSON`, `signature`) produced with
  `challenge = event_hash`. The verifier MUST check, against the signer's key (§5.1):
  - `clientDataJSON.type == "webauthn.get"`;
  - `clientDataJSON.challenge == base64url(event_hash)`;
  - `clientDataJSON.origin` is `https://<rpId>` or a subdomain of it (`http://localhost` allowed for testing);
  - `crossOrigin` is not `true`;
  - `authenticatorData[0..32] == SHA-256(rpId)`, and the user-presence flag is set;
  - the signature over `authenticatorData ‖ SHA-256(clientDataJSON)` verifies with the key's algorithm
    (ES256 with DER-encoded signatures, RS256, or EdDSA).

Verifiers SHOULD report whether the user-verified flag (PIN or biometrics) was set.

## 4. Documents

Documents are never put in the log. An event commits to each one:

```
commitment = SHA-256( "hardstate/doc/v1" ‖ salt ‖ SHA-256(file) )      salt: 32 random bytes
```

The salt prevents guessing a document from its commitment (many public documents have low entropy: IDs, amounts,
templates). Whoever holds the salt (the citizen, through their receipt; the institution) can prove that a file is the
recorded one. An issuer MAY **publish** a document: it then reveals `salt` and `SHA-256(file)` and makes the file
available; anyone can then check and find it by its plain SHA-256.

Receipts carry salts in the URL fragment (`/r/<event_hash>#k=<commitment[0..16]>.<salt>,…`), which browsers never send
to servers.

## 5. The issuer's keys live in its own log

| Type | Meaning | Signed by |
|---|---|---|
| `issuer.create` | `seq 0`. `public.name`, optional `public.jurisdiction`/`website`, and `public.key` (the founding admin key). | the key it declares |
| `key.add` | `public.key`: a new key. | an active `admin` (§5.4) |
| `key.revoke` | `public.keyId`, optional `public.reason`. The last active institution admin MUST NOT be revoked. | an active `admin` (§5.4) |
| `key.move` | `public.keyId`, `public.dept` (a department id, or `null` for the institution itself). | an institution `admin`, or a head over both places |
| `issuer.update` | Profile changes (merged into the profile). | an institution `admin` |
| `dept.add` | `public.dept`: `{ id, name, parent?, types? }` (§5.4). | an institution `admin`, or a head over `parent` |
| `dept.update` | `public.dept`: `{ id, name?, types?, closed? }`. | an institution `admin`, or a head over it |
| `session.open` | `public.key`: a session key (§5.2), optional `public.device`. | an active `admin` or `official` |
| `session.close` | `public.keyId` of an open session. | the person who opened it, the session itself, or an `admin` |

Every other event MUST be signed by a key that is active at that `seq` (added at a lower `seq`, not revoked at a
lower `seq`) and allowed by its scope (§5.1). Revocation does not invalidate earlier signatures. Revoking a person's
key (`key.revoke`) also closes every session they opened, at the same `seq`.

Every other type in the reserved domains (`issuer.*`, `key.*`, `session.*`, `dept.*`) MUST be refused. Event types
outside them are the issuer's own vocabulary (`domain.action`, e.g. `permit.approve`,
`aid.delivered`, `diploma.issue`): institutions define them when they integrate.

### 5.0 Profile fields (issuer.create / issuer.update `public`)

| Field | Meaning |
|---|---|
| `name` | REQUIRED in issuer.create. Display name. |
| `jurisdiction` | Human-readable place ("Esperanza, Sonora, Mexico"). |
| `location` | OPTIONAL `{ country, region?, locality?, lat?, lon? }`: `country` is ISO 3166-1 alpha-2; `lat`/`lon` in decimal degrees. Captured at registration so coverage maps are derived from signed data. |
| `website` | OPTIONAL URL. |
| `demo` | OPTIONAL `true` for test or demonstration issuers. Explorers and coverage indexes SHOULD list them apart and MUST NOT count them in public figures. |

`issuer.update` merges its `public` fields into the profile (the `key` field is ignored there).

### 5.1 Key object

```json
{ "id": "…", "kind": "passkey" | "ed25519", "alg": -7 | -257 | -8, "publicKey": "<SPKI DER, base64url>",
  "role": "admin" | "official" | "system" | "session", "label": "Building inspector",
  "holder": "<hex sha256(\"hardstate/holder/v1\" ‖ salt ‖ name)>",
  "rpId": "app.hardstate.net", "scope": { "types": ["case.*", "fee.paid"], "expires": "2026-10-20T20:00:00Z" },
  "dept": "permits" }
```

- Passkeys: `id` is the WebAuthn credential id (base64url); `rpId` is REQUIRED.
- Ed25519 keys: `alg` MUST be `-8`; `id` is `"ed25519:" + hex(SHA-256(spki)[0..16])`.
- `label` is public and says *what* the key is, never *who* holds it: a person's title ("Building inspector"), a
  system's name ("Payments gateway"), a session's device. It MUST NOT contain a person's name. HSS exposes
  institutions and their procedures, not their officials.
- `holder` (optional, people only): `hex(SHA-256("hardstate/holder/v1" ‖ salt ‖ UTF-8(name)))`, the name in Unicode
  NFC with surrounding and repeated whitespace collapsed, `salt` 16 random bytes. The institution keeps the name and
  salt (an operator MAY hold them for it, never in the log); revealing both proves who held the key, as documents are
  opened in §4. Person keys SHOULD carry one.
- **Key code.** Every key has a public code: the first 30 bits of
  `SHA-256("hardstate/key-code/v1" ‖ issuer ‖ 0x00 ‖ key.id)` in Crockford base32 (`0123456789ABCDEFGHJKMNPQRSTVWXYZ`),
  6 characters, e.g. `D12SX3`. It is how records, receipts and explorers name the signer, with its `label` and
  department. A `key.add` or `session.open` whose key's code equals that of any key already in the log MUST be
  refused (the holder generates another key).
- `scope` (optional): `types` lists the event types the key may sign, exactly or with a trailing wildcard
  (`"case.*"`); `expires` is the last instant (`event.ts`) it may sign. A scope MUST NOT grant types in the reserved
  domains.
- `dept` (optional): the department the key belongs to (§5.4). Absent, the key belongs to the institution itself.
  Session keys MUST NOT carry one: a session answers to its person's department.
- Roles: `admin` and `official` are people. `system` is a process with no person behind it (a payments gateway, a case
  system) and MUST carry `scope.types`; it is added by an admin with `key.add`. `session` keys exist only through
  `session.open`. `system` and `session` keys MUST NOT sign `issuer.*`, `key.*` or `session.open`.

### 5.2 Delegated sessions

So that officials do not sign every step by hand, a person can delegate to a device or system:

- `session.open`, signed by the person's key, declares a session key: `kind: "ed25519"`, `role: "session"`,
  `scope.expires` REQUIRED and at most **30 days** after the event's `ts`, optional `scope.types`.
- Events signed by the session key are **attributed to the person** who opened it. Verifiers MUST show that person,
  and SHOULD show the session's label and expiry.
- A session ends at `scope.expires`, with `session.close`, or when the person's key is revoked.
- Operators MUST refuse a session-signed event received more than 5 minutes after `scope.expires`. Verifiers MUST
  refuse one whose `ts` is after `scope.expires`, and one first proven on Bitcoin more than **6 hours** after
  `scope.expires` (a stolen session key cannot back-date events past its life).
- Session keys SHOULD be non-exportable where they live (WebCrypto non-extractable keys, HSM, KMS).

### 5.3 Binding an issuer to a real institution

An issuer id is just a name. An institution binds its log to a domain it is known by in both directions:

1. its profile, signed in the log (`issuer.create` or a later `issuer.update`), declares `"website": "https://<domain>"`;
2. the domain names the log, in either of two places:

```
https://<domain>/.well-known/hardstate.json   →   { "issuer": "<id>", "genesis": "<event_hash of seq 0>" }
_hardstate.<domain>  TXT                      →   "issuer=<id> genesis=<event_hash of seq 0>"
```

Both MUST hold. The second alone proves nothing, since anyone can copy an issuer's public id and genesis onto a domain
they control. A binding ends when a later profile declares another `website`. Verifiers and explorers SHOULD show the
verified domain next to the issuer's name and SHOULD warn when there is none.

### 5.4 Departments

Real institutions have a middle level: offices that run their own procedures and their own people. A department is
declared in the log, so who answers for what is anchored history too.

- `dept.add` declares `{ id, name, parent?, types? }`: `id` is a lowercase slug (`^[a-z0-9][a-z0-9-]{0,47}$`),
  permanent, never reused; `name` is public; `types` (optional) lists the event types its keys may sign, exactly or
  with a trailing wildcard, never types in the reserved domains.
- `parent` (optional) nests it inside an open department: a ministry's secretariats, their directorates, their
  offices. Departments nest at most **4** levels deep (a top-level department counts as one). A department keeps the
  place its `dept.add` gave it: `dept.update` MUST NOT carry `parent`.
- `dept.update` changes `name` or `types` (`types: null` removes the limit), or closes the department with
  `closed: true`. A department MUST have no active keys (other than sessions) and no open departments under it when it
  closes. A closed department takes no new keys or departments and does not reopen.
- A key belongs to the department in its `key.add` (`public.key.dept`), until a `key.move` sets another one or `null`.
  The department MUST exist and be open at that `seq`.
- An **institution admin** is an `admin` key without a department: it manages every key and department, and alone
  signs `issuer.update` and top-level `dept.add`. A **department head** is an `admin` key with a department; its
  *branch* is that department and every department under it. A head MAY sign `key.add` for keys of its branch
  (officials, systems, other heads), `key.revoke` and `session.close` for keys that answer to its branch, `key.move`
  between places in its branch, `dept.add` with a `parent` in its branch, and `dept.update` for departments under its
  own (never its own: its limits are set from above). The last institution admin MUST NOT be revoked or moved into a
  department.
- Every event other than §5's types, signed by a key of a department (or by a session of a person in one), MUST be
  allowed by the `types` of that department and of every department above it, in addition to the key's own `scope`:
  a department never signs more than the one it sits in. A change of `types` or a `key.move` applies from its `seq`
  on; earlier events are judged by the state at their own `seq`.
- A proof's authority chain (§9) carries the `dept.add` / `dept.update` events before the event and the `key.move` of
  every key in the chain, each signed by a key the chain establishes. Rules that need every key (closing empty, keeping
  an institution admin) are checked by verifiers holding the full log.

Operators MAY limit how many departments an issuer has open (a plan; nested ones count like any other), and MUST NOT
otherwise refuse a valid `dept.*`.

## 6. Batches

An operator periodically (reference: every 10 minutes) closes a batch over the events and stamps it has received.

- Leaf data: one kind byte followed by the 32-byte hash: `0x01 ‖ event_hash` for events, `0x02 ‖ digest` for stamps
  (bare SHA-256 digests submitted by anyone, §8).
- Tree: RFC 9162 (Certificate Transparency v2) Merkle Tree Hash: `leaf = SHA-256(0x00 ‖ data)`,
  `node = SHA-256(0x01 ‖ left ‖ right)`, split at the largest power of two smaller than `n`.
- The operator MUST publish each batch's ordered leaf list, so anyone can recompute the root.
- Inclusion proofs are RFC 9162 audit paths (`index`, `size`, `path`).

## 7. Anchoring to Bitcoin

### 7.1 OpenTimestamps (every batch)

The batch root is submitted to at least two public OpenTimestamps calendars, using the reference client's construction
(`append(16 random bytes)`, `sha256`, submit). The resulting `.ots` file, once upgraded, contains a path from the batch
root to a Bitcoin block's merkle root. It MUST be a standard detached `.ots` file over the batch root, so that
`ots verify -d <root> <file>.ots` works independently of HardState.

### 7.2 HardState Anchor (daily)

The operator builds a tree (§6 rules, leaf data `0x03 ‖ batch_root`) over every batch root not yet anchored, and
writes its root in a Bitcoin transaction output:

```
OP_RETURN  PUSH36( "HSS" ‖ 0x01 ‖ root32 )          script: 6a 24 48 53 53 01 <32 bytes>
```

36 bytes of payload, within every common relay policy (including Bitcoin Knots' 40-byte default). The operator SHOULD
publish its anchoring address and every anchor's fee. An anchor on a test network (signet) MUST be labelled as such by
verifiers and MUST NOT count as a Bitcoin proof.

## 8. Citizen stamps

Anyone MAY submit a bare SHA-256 digest (no account, no issuer). It goes into the next batch as a `0x02` leaf. This
lets citizens, journalists or NGOs anchor what they received or filed, without the institution's cooperation.

## 9. HardState Proof (`.hardstate.json`)

```json
{
  "hardstate": "proof", "hss": 1,
  "subject": { "kind": "event", "signed": { "event": {…}, "sig": {…} }, "hash": "…" }
           | { "kind": "stamp", "digest": "…" },
  "authority": [ /* issuer.create, the key.add / session.open events establishing the signer, and the
                   dept.add / dept.update / key.move events that shape it (§5.4), ascending seq */ ],
  "batch":  { "id": "…", "closedAt": "…", "root": "…", "size": 8, "index": 5, "path": ["…"] },
  "ots":    "<base64 of the detached .ots for batch.root>",
  "anchor": { "network": "bitcoin" | "signet", "txid": "…", "root": "…", "size": 1, "index": 0, "path": [] },
  "logUrl": "https://api.hardstate.net/v1/issuers/<id>/log",
  "issuedAt": "…"
}
```

`batch`, `ots` and `anchor` are absent while not yet available; a proof can be fetched again later to complete it.

## 10. Verification

A verifier MUST perform, and SHOULD show, each step:

1. **Integrity.** `SHA-256(canonical(subject.signed.event)) == subject.hash`.
2. **Signature and authority.** Starting from `issuer.create` (self-signed), each `key.add`, `session.open`,
   `dept.add`, `dept.update` or `key.move` in `authority` is signed by a key established earlier and allowed to sign it
   (§5, §5.4); the event's `actor` is established at a lower `seq`; its scope, and its department's `types`, allow the
   event's type and `ts`; the signature verifies (§3.3). For a session key, the verdict names the person who opened
   it, and the session-expiry rule of §5.2 applies against Bitcoin time. The verdict names the signer by its key code,
   `label` and department (§5.1), never by a person's name.
3. **Batch.** The leaf (`0x01 ‖ hash` or `0x02 ‖ digest`) with `batch.path` yields `batch.root`.
4. **OpenTimestamps.** The `.ots` file is for `batch.root`; for each Bitcoin attestation at height `h`, the attested
   message equals the merkle root (internal byte order) of block `h`. The block header MUST be obtained from at least
   two independent sources (explorers or the verifier's own node) that agree.
5. **Anchor.** `0x03 ‖ batch.root` with `anchor.path` yields `anchor.root`; transaction `anchor.txid` carries the
   §7.2 script for `anchor.root` and is confirmed; same two-source rule.
6. **Document** (optional). With a file and its salt, the recomputed commitment is one of `event.docs`.
7. **Completeness** (optional, online). The issuer's full log replays from `seq 0` under §5 without error, and holds
   this exact event at its `seq`.

**Verdict:** *invalid* if any performed step fails; *valid* if 1–3 pass and at least one of 4 or 5 passes on Bitcoin
mainnet; otherwise *pending*. The earliest confirmed block time is reported as "existed before".

## 11. Security notes and limits

- **Officials are not exposed.** The log is public and permanent, so it never carries a person's name: keys are
  named by code, title and department (§5.1). Who held a key is a salted commitment the institution can open for an
  auditor or a court. Titles can still identify someone in a one-person office; institutions SHOULD choose them
  accordingly.
- **Garbage in.** HSS proves that an issuer said something at a time, signed by a named key. It does not prove the
  statement is true.
- **Omission.** An act that is never recorded leaves no trace. Mitigations: receipts at every step (citizens can
  demand the next one), citizen stamps (§8), and procedures whose next step requires the previous event's hash.
- **Withholding by an operator.** An operator can delay or refuse to include events. Issuers SHOULD use more than one
  operator; logs are portable, since every event is self-contained and signed.
- **Truncation of the tail.** Removing the newest *anchored* events is detectable: the batch leaf lists (§6) are
  committed in Bitcoin. Events not yet anchored can be withheld; that window is at most one batch interval plus the
  OpenTimestamps confirmation delay.
- **Key compromise.** Revoke at once (`key.revoke`); signatures made before the revocation remain attributable to
  the key, and it is the institution's responsibility to correct them with new events.
- **Passkeys vs. qualified signatures.** A passkey proves a device and a present (usually verified) user. It is not a
  qualified electronic signature (eIDAS, e.firma). HSS can carry such signatures in a future `kind`.
- **Privacy.** Only hashes reach Bitcoin. `public` and published documents are public by the issuer's choice; never put
  personal data there.

## 12. Versioning

Changes that alter hashing, signing or verification increment `hss`. Verifiers MUST reject versions they do not know.
