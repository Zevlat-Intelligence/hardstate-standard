# Security

HardState's promise is that no one can quietly rewrite, hide or back-date a public record. A flaw that breaks that
promise matters more than any other bug, so please report it privately.

**How to report:** use GitHub's private vulnerability reporting on
[hardstate-standard](https://github.com/Zevlat-Intelligence/hardstate-standard) (*Security* tab → *Report a
vulnerability*), or write to hello@hardstate.net. Include what an attacker can do, the steps to reproduce it, and the
affected component (spec, `@hardstate/core`, API, app). Please don't open a public issue or test against other
people's institutions.

**In scope, most wanted:**
- a record, document or proof that the verifier accepts although it was changed, removed, re-ordered or back-dated;
- an event accepted by the API without a signature from a key the issuer's own log authorizes (roles, scopes,
  sessions, revocations);
- a way to make the browser verifier trust the HardState server instead of the signatures and Bitcoin;
- disclosure of a document's content or salt that the citizen did not share.

**Also welcome:** denial of service on the API beyond the per-address rate limits, and problems in how anchors are
built or spent.

**Out of scope:** findings that need control of the user's device or passkey, social engineering, and reports from
automated scanners without a working impact.

We will acknowledge a report within a few days, keep you posted while we fix it, and credit you in the release notes
unless you prefer otherwise.
