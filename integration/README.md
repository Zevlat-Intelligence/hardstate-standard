# Integrating HardState into an institution's software

The goal: **nobody opens a console to record each step.** Officials authorize once; the institution's own software
records every checkpoint (a case opened, an inspection, an approval, a payment) automatically, and gives the citizen
a receipt. The institution's only ongoing task is its subscription.

Everything below uses the public API, `https://api.hardstate.net` (`http://localhost:8787` when running locally).
Spec: [`../spec/HSS-1.md`](../spec/HSS-1.md). API contract: [`../spec/openapi.yaml`](../spec/openapi.yaml).

## 1. Choose who signs

| Signer | When to use | How it is authorized | Attributed to |
|---|---|---|---|
| **Session of a person** (`role: session`) | A clerk's or inspector's workstation, tablet or field app during their shift | The person approves it once with their passkey (`session.open`); it expires (≤ 30 days) | **That person**, by name |
| **System key** (`role: system`) | A process with no person behind it: payment gateway, appointment system, scanner | An admin registers it once (`key.add`), limited to some step types | The system, by name |
| **Passkey, step by step** | Low volume, or high-stakes acts that must be signed in person | Already registered in the institution's log | That person |

Prefer sessions for anything a person is responsible for: accountability stays personal, and a lost device is closed
in one click. Use system keys only for steps that no person performs, and always scope them
(`"types": ["fee.paid"]`).

## 2. Event types are yours

Each step is an event of a type you choose, `domain.action` in lowercase: `case.open`, `case.inspect`,
`permit.approve`, `permit.deny`, `fee.paid`, `diploma.issue`, `aid.delivered`, `contract.award`,
`land_title.transfer`… Only `issuer.*`, `key.*` and `session.*` are reserved by the protocol. Keep one type per kind of
act, put the act's public facts in `public`, and use `case` for the file or procedure number, so a citizen's whole
procedure reads as one timeline.

## 3. Authorize your software (once)

Your software generates its own Ed25519 key pair and keeps the private key (a file with permissions 0600, or better
an HSM or a cloud KMS). It then asks to be authorized with a **request link**:

```
https://app.hardstate.net/console?device=<base64url(JSON)>
JSON = { "v": 1, "label": "Permits system — City Hall", "publicKey": "<SPKI DER, base64url>", "types": ["case.*", "permit.*"] }
```

Open the link signed in to the console (Devices & sessions):

- an **official** approves it as *their* session, for a chosen time;
- an **admin** can instead register it as a **system** key, valid until revoked.

The key id your software must use as `actor` is `"ed25519:" + hex(SHA-256(spki))[0:32]`.

## 4. Record each checkpoint: prepare → sign → submit

Any language that can make an HTTP request and an Ed25519 signature can integrate. No canonical-JSON library is
needed: the API prepares the exact event for you.

1. `POST /v1/events/prepare` with the step: `{ issuer, type, case, public, docs, actor }`.
   It answers with `{ event, canonical, hash, challenge }`, where `event` sits on the current head of your log.
2. **Check `event`** against what you sent, then sign the 32 bytes of `hash` with your Ed25519 key.
3. `POST /v1/events` with `{ event, sig: { kind: "ed25519", signature: <base64url> } }`.
   It answers `201` with `{ hash, seq, receipt, proof }`. On `409` another step got there first: prepare again.

### cURL (step 1 and 3)

```bash
curl -s https://api.hardstate.net/v1/events/prepare -H 'content-type: application/json' -d '{
  "issuer": "city-of-esperanza", "type": "permit.approve", "case": "BP-2026-0042",
  "public": { "decision": "approved", "validUntil": "2027-10-20" }, "actor": "ed25519:4be1…"
}'
# … sign .hash, then:
curl -s https://api.hardstate.net/v1/events -H 'content-type: application/json' \
  -d '{ "event": { … the event returned by prepare … }, "sig": { "kind": "ed25519", "signature": "…" } }'
```

### Python

```python
import base64, hashlib, json, urllib.request
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

API = "https://api.hardstate.net"
b64url = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()

def post(path, body):
    req = urllib.request.Request(API + path, json.dumps(body).encode(), {"content-type": "application/json"})
    with urllib.request.urlopen(req) as r:
        return json.load(r)

key = Ed25519PrivateKey.generate()          # load yours from a protected file, HSM or KMS
spki = key.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
actor = "ed25519:" + hashlib.sha256(spki).hexdigest()[:32]
request_link = "https://app.hardstate.net/console?device=" + b64url(json.dumps(
    {"v": 1, "label": "Permits system", "publicKey": b64url(spki), "types": ["permit.*"]}).encode())

def record(issuer, type_, case, public, docs=()):
    p = post("/v1/events/prepare", {"issuer": issuer, "type": type_, "case": case, "public": public,
                                     "docs": list(docs), "actor": actor})
    assert p["event"]["type"] == type_ and p["event"]["public"] == public   # sign only what you meant
    sig = key.sign(bytes.fromhex(p["hash"]))
    return post("/v1/events", {"event": p["event"], "sig": {"kind": "ed25519", "signature": b64url(sig)}})

r = record("city-of-esperanza", "permit.approve", "BP-2026-0042", {"decision": "approved"})
print(r["receipt"])   # put this link (and its QR) in the notification you already send to the citizen
```

### Node / TypeScript (SDK)

```ts
import { HardStateClient, signEd25519 } from "@hardstate/core";
const client = new HardStateClient("https://api.hardstate.net");
const r = await client.append(
  { issuer: "city-of-esperanza", type: "permit.approve", case: "BP-2026-0042", actor, public: { decision: "approved" } },
  (event) => signEd25519(event, privateKey),        // CryptoKey (Ed25519)
);
console.log(r.receipt);
```

The SDK builds the canonical event itself, so it never relies on the server's `prepare`. It also retries on `409`.

## 5. Documents

Never send documents to HardState unless the institution decides to publish them. Commit to each file instead:

```
digest     = SHA-256(file)
salt       = 32 random bytes            (keep it: it goes in the citizen's receipt)
commitment = SHA-256("hardstate/doc/v1" ‖ salt ‖ digest)
docs       = [{ "label": "Inspection report", "commitment": hex(commitment), "mime": "application/pdf" }]
```

Give the citizen the receipt link with the salts in its fragment:
`<receipt>#k=<commitment[0:16]>.<salt hex>,…`. The fragment never reaches any server; with it, anyone holding the file
can check it is the recorded one. To publish a document, send `publish: [{ commitment, digest, salt }]` with the
event, then `PUT /v1/docs/<commitment>` with the file bytes.

## 6. Receipts for citizens

`POST /v1/events` returns `receipt` (`https://app.hardstate.net/r/<hash>`). Append the `#k=…` fragment if the step
has documents, and put the link and its QR in what the citizen already receives (email, SMS, the printed form). Every
step of the case links to the full timeline.

## 7. Operating it

- **Custody.** System and session private keys never leave the machine that uses them (permissions 0600, HSM/KMS).
  If one leaks: close the session or revoke the system key from the console. Everything signed before stays
  attributable, which is the point.
- **Scope.** Give each key the narrowest `types` that works.
- **Retries.** `409` means the log head moved: prepare again. Network errors are safe to retry with the same signed
  event: a duplicate is refused, not recorded twice.
- **Retries on `402`.** The monthly fair-use limit of the plan is spent (with a 10% grace). Key, session and profile
  events still go through; procedure steps resume on the 1st (UTC) or right after an upgrade. Watch
  `GET /v1/issuers/{id}/account` (`usage.records`, `limits.records`, `overLimit`) to see it coming.
- **Pace.** Records reach Bitcoin within 1–3 hours via OpenTimestamps (free) and in the daily HardState Anchor. Paid
  plans also get hourly anchors and express anchors (~10–20 min), from the console or `POST /v1/anchors/express`.

## 8. Plan and billing

Plans and prices: `GET /v1/plans` and [app.hardstate.net/pricing](https://app.hardstate.net/pricing). Citizens never
pay, and Community is free for public-interest institutions. An admin chooses a plan in the console (**Plan &
billing**): by card or local method through Stripe Checkout, monthly or yearly, or **by invoice** (net 30, with the
purchase order on it, payable by bank transfer). The Stripe Customer Portal changes the plan, the payment method or the
billing details, and cancels at the end of the period.

There is no billing login. Each billing action is an *operator request*, signed like an event by an admin key that the
institution's own log authorizes:

```json
{ "request": { "op": "billing.checkout", "issuer": "your-id", "key": "<admin key id>", "ts": "2026-10-21T18:00:00Z",
               "nonce": "<16 random bytes, base64url>", "params": { "plan": "institution", "interval": "year" } },
  "sig": { "kind": "passkey", "authenticatorData": "…", "clientDataJSON": "…", "signature": "…" } }
```

The signed hash is `sha256("hardstate/operator/v1" ‖ JCS(request))`: a passkey uses it as the WebAuthn challenge, an
Ed25519 key signs it directly (`HardStateClient.operator()` does both). The operator accepts it within 5 minutes of
`ts`, once per nonce, and only from a live admin key. Operations: `billing.checkout`, `billing.invoice` (params:
`plan`, `interval`, `email`, `name`, `address`, optional `taxId` and `po`), `billing.portal` and `anchor.express`.
Downgrading or cancelling never touches what was recorded: every proof keeps verifying against Bitcoin.
