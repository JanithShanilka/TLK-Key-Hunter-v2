# Live-session secrets and offline recovery

## Confirmed finding

Successful secret recovery and traffic decryption were demonstrated for all 20 tested TLS 1.2 sessions. Nineteen sessions completed automatically; one required correction of a permissions issue followed by reanalysis of its existing memory dump.

For every recovered session, the selected 48-byte master secret matched the independent server reference exactly (zero differing bits out of 384), and both the captured HTTP request and response were decrypted. These are successes for every session **in this experiment**, not a guarantee for arbitrary TLS connections.

## Evidence flow

Live Firefox connection → saved process memory → reference-blind candidate extraction → saved-traffic validation → independent exact-secret comparison and controlled-marker verification.

The server reference was recorded during the live handshake and withheld from the extractor. The private report displays those recorded values, not a current live feed. Memory-only ranking had ties; packet validation selected the winner. The 96 candidate checks across all 20 sessions, including the repaired first attempt, produced 20 passes and 76 failures. They are not 96 independent session experiments.

| Session | Case | Candidates | Differing bits / 384 | HTTP request | HTTP response | Completion |
|---|---|---:|---:|---|---|---|
| 01 | TLS12-REPEAT-20260928-A-001 | 5 | 0 | Yes | Yes | After permissions repair |
| 02 | TLS12-REPEAT-20260928-B-001 | 5 | 0 | Yes | Yes | Automatic |
| 03 | TLS12-REPEAT-20260928-B-002 | 4 | 0 | Yes | Yes | Automatic |
| 04 | TLS12-REPEAT-20260928-B-003 | 5 | 0 | Yes | Yes | Automatic |
| 05 | TLS12-REPEAT-20260928-B-004 | 5 | 0 | Yes | Yes | Automatic |
| 06 | TLS12-REPEAT-20260928-B-005 | 4 | 0 | Yes | Yes | Automatic |
| 07 | TLS12-REPEAT-20260928-B-006 | 5 | 0 | Yes | Yes | Automatic |
| 08 | TLS12-REPEAT-20260928-B-007 | 5 | 0 | Yes | Yes | Automatic |
| 09 | TLS12-REPEAT-20260928-B-008 | 5 | 0 | Yes | Yes | Automatic |
| 10 | TLS12-REPEAT-20260928-B-009 | 5 | 0 | Yes | Yes | Automatic |
| 11 | TLS12-REPEAT-20260928-B-010 | 5 | 0 | Yes | Yes | Automatic |
| 12 | TLS12-REPEAT-20260928-B-011 | 5 | 0 | Yes | Yes | Automatic |
| 13 | TLS12-REPEAT-20260928-B-012 | 5 | 0 | Yes | Yes | Automatic |
| 14 | TLS12-REPEAT-20260928-B-013 | 5 | 0 | Yes | Yes | Automatic |
| 15 | TLS12-REPEAT-20260928-B-014 | 4 | 0 | Yes | Yes | Automatic |
| 16 | TLS12-REPEAT-20260928-B-015 | 5 | 0 | Yes | Yes | Automatic |
| 17 | TLS12-REPEAT-20260928-B-016 | 5 | 0 | Yes | Yes | Automatic |
| 18 | TLS12-REPEAT-20260928-B-017 | 4 | 0 | Yes | Yes | Automatic |
| 19 | TLS12-REPEAT-20260928-B-018 | 5 | 0 | Yes | Yes | Automatic |
| 20 | TLS12-REPEAT-20260928-B-019 | 5 | 0 | Yes | Yes | Automatic |

## Preserve both results

- Initial unattended completion: 19/20 (95% observed).
- Eventual exact recovery and decryption, including separate reanalysis: 20/20.
- Unique memory-only selection in the 19 continuation sessions: 0/19; four or five top candidates remained tied.
- Test scope: Firefox 136.0.2/NSS, Linux x86-64, one localhost TLS 1.2 ECDHE-RSA-AES128-GCM-SHA256 connection per fresh profile. Approved temporary socket-sandbox and certificate-validation exceptions applied.

## Saved artifacts

The [redacted visual report](LIVE_SESSION_SECRETS_AND_OFFLINE_RECOVERY.html) preserves the original 20-session report layout and every candidate's score, differing-bit count and pass/fail outcome. Actual secret values are replaced with a redaction label. The full private report remains outside Git at `output/offline-memory/campaign-keys.private.html`; it is not backed up to GitHub. Small private evidence remains on the lab host.

The [detailed repeatability analysis](REPEATABILITY_RESULTS.md), [work log](SAVED_MEMORY_WORK_LOG.md), and `campaigns/` JSON/CSV records preserve the experimental history. Campaign dumps and temporary profiles were deleted after results were saved.

The [TLS 1.3 pilot plan](TLS13_OFFLINE_PILOT_PLAN.md) describes the next test. No TLS 1.3 offline recovery result is claimed.
