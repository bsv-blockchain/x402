---
'@x402/bsv': minor
---

Added BSV `upto` client, server, and facilitator support alongside `exact`. The payer authorizes a maximum once; the recipient settles the actual amount in one transaction and returns its Atomic BEEF through the existing settlement response. Includes multi-input/output validation, source reservation interfaces, and single-use coordination.
