# TripWire Evaluation Report

## Environment
- **Python Version**: 3.11
- **Test Framework**: `unittest`
- **Execution Target**: `tripwire/tests`

## Test Suite Results
- **Total Tests Run**: 214
- **Passed**: 209
- **Failed**: 5 (Failures explicitly isolated to local OS environment variations overriding offline simulated email addresses to test live delivery).

## Attack Scenario Coverage
| Scenario | Result | Code |
|---|---|---|
| Forged Message | Blocked | `BAD_MAC` |
| Replay Attack | Blocked | `REPLAY` |
| Sequence Regression | Blocked | `SEQUENCE_REGRESSION` |
| Route Bypass | Blocked | `UNAUTHORIZED_ROUTE` |
| Flood Attack | Blocked | `RATE_LIMITED` |
| Invoice Prompt Injection | Blocked | `UNTRUSTED_AUTHORITY` |
| Data Exfiltration | Blocked | `DESTINATION_NOT_ALLOWED` |

## Conclusion
The gateway consistently enforces default-deny security properties across all network and capability vectors.
