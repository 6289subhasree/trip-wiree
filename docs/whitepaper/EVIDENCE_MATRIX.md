# Evidence Matrix

| Security Claim | Source File | Implementation Evidence | Test Evidence | Status |
|---|---|---|---|---|
| HMAC Authentication | `protocol.py` | `HMAC-SHA256` tag verification | `test_tampered_payload_is_rejected` | Implemented and tested |
| 30s Freshness Window | `protocol.py` | `abs(now - ts) > 30` | `test_stale_and_future_messages` | Implemented and tested |
| Replay Cache | `protocol.py` | `nonce_cache` lookup | `test_replay_is_rejected` | Implemented and tested |
| Rate Limiting | `gateway.py` | Token bucket (12 burst, 2/s) | `test_flood_is_bounded` | Implemented and tested |
| Provenance Checks | `tools_gateway.py` | `UNTRUSTED_AUTHORITY` logic | `test_untrusted_authority` | Implemented and tested |
| Canary Egress | `tools_gateway.py` | String match against `canary_vault` | `test_canary_egress` | Implemented and tested |
| Audit Chaining | `audit.py` | `HMAC(last_hash + event)` | `test_chain_verifies_and_detects` | Implemented and tested |
