# HardState Receipt

**Public records that no one can rewrite. Not even the government.**

This repository holds what anyone needs to check a [HardState](https://hardstate.net) receipt on their own, without
trusting the institution that issued it or HardState:

```
FORMAT.md    The HardState Receipt Format (HRF-1): the bytes a verifier checks.
receipt/     @hardstate/receipt: the reference verifier. Isomorphic (WebCrypto + fetch), no HardState server involved.
```

HardState itself (the service, the HardState Protocol, the console and the brand) is a product of Zevlat Intelligence
and is not in this repository.

## Verify a receipt

**In a browser:** open the receipt, or drop a `.hardstate.json` file or a document on https://app.hardstate.net/verify.
The check runs on your machine.

**In code:**

```ts
import { verifyReceipt } from "./receipt/src/index.ts";

const verdict = await verifyReceipt(proof);        // proof: the parsed .hardstate.json
console.log(verdict.status, verdict.steps);        // valid / pending / invalid, and each step
```

Only public Bitcoin explorers are read, and at least two of them must agree.

**With the OpenTimestamps client**, without any HardState code:

```bash
pip install opentimestamps-client
ots verify -d <batch root> batch.ots
```

## License

`FORMAT.md` is CC BY-ND 4.0 (`LICENSE-FORMAT`). `@hardstate/receipt` is Apache-2.0 (`LICENSE`).

## Develop

```bash
npm install
npm test
```

---

HardState is a [Zevlat Intelligence](https://zvlint.com) venture.
