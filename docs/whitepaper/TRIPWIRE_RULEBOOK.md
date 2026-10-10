# TripWire Security Rule Reference

| Rule ID | Layer | Description | Outcome |
|---|---|---|---|
| `BAD_MAC` | Protocol | HMAC signature validation failed | BLOCK + Risk |
| `STALE` | Protocol | Message timestamp is >30s old | BLOCK |
| `REPLAY` | Protocol | Nonce has been seen in cache | BLOCK + Risk |
| `SEQUENCE_REGRESSION` | Protocol | Sequence ID out of order | BLOCK |
| `UNAUTHORIZED_ROUTE` | Protocol | Sender not allowed to message Recipient | BLOCK + Risk |
| `RATE_LIMITED` | Protocol | Token bucket exceeded (12 burst, 2/sec) | BLOCK |
| `UNTRUSTED_AUTHORITY` | Capability | Instruction origin is an untrusted document | BLOCK + High Risk |
| `DATA_OUT_OF_SCOPE` | Capability | Requested data not listed in Manifest | BLOCK + High Risk |
| `DESTINATION_NOT_ALLOWED` | Capability | Target URL/Email not in allowlist | BLOCK + High Risk |
| `INTENT_MISMATCH` | Capability | Tool semantics do not match manifest intent | BLOCK |
| `CANARY_EGRESS` | Post-event | Honeytoken detected in outgoing payload | LOCKDOWN |
