---
'@x402/bsv': minor
---

Extend the BSV mechanism with the `upto` scheme. Clients create a reusable maximum-payment authorization, recipients determine the actual satoshi amount in a fully signed transaction, and one-shot or cumulative streaming workflows share the existing BRC-29, BEEF, and recipient-wallet settlement path. Add role-specific `@x402/bsv/upto/client`, `@x402/bsv/upto/server`, and `@x402/bsv/upto/facilitator` entrypoints.
