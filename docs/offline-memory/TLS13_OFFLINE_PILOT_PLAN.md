# TLS 1.3 saved-memory pilot — feasibility demonstrated; campaign pending

## Objective

Repeat the same evidence flow with Firefox and a controlled localhost TLS 1.3 connection: save browser process memory, extract candidates without the independent reference, validate with captured traffic, and compare selected secrets with the isolated server reference. Recovery is an open experimental question. Historical live-hook results do not establish offline recovery.

## Protocol changes that matter

TLS 1.3 has separate client/server handshake and application traffic secrets. Their length follows the cipher suite's hash: 32 bytes for SHA-256 or 48 for SHA-384. Traffic keys and IVs are derived from these secrets; KeyUpdate advances their generation. Handshake secrets can be erased after use, so capture timing matters. See [RFC 8446 key schedule](https://www.rfc-editor.org/rfc/rfc8446.html#section-7.1), [updates](https://www.rfc-editor.org/rfc/rfc8446.html#section-7.2), and [key derivation](https://www.rfc-editor.org/rfc/rfc8446.html#section-7.3).

The first target is both generation-zero application traffic secrets, for the request and response directions. Report handshake-secret recovery separately if needed for the packet decoder. A reference-supplied handshake secret must not be silently included in an extractor-only decryption claim. The existing 48-byte TLS 1.2 CKA_VALUE rule has not been validated for these objects.

## Minimal pilot sequence

1. Keep the established TLS 1.2 implementation and results intact. Create a separate TLS 1.3 pilot case and record executable/library hashes and all compatibility exceptions.
2. Constrain client/server to TLS 1.3, one full handshake and one controlled HTTP connection. Begin with AES-128-GCM/SHA-256 if the installed server API supports explicit suite configuration; otherwise record the actual negotiated suite and use its hash length. Exclude resumption, early data and intentional key updates from this first scope; check the captured negotiation.
3. Record independent server references privately, inaccessible to the researcher running extraction. Do not enable Firefox key logging, use Frida secret-export hooks or inject reference bytes into Firefox.
4. Capture once after the controlled request/response begins while the connection is held open. Save packet capture, process ownership, acquisition times, mapping warnings and integrity hashes.
5. Adapt candidate discovery to the relevant NSS structures and hash-dependent lengths. Do not merely scan every random-looking 32-byte window and label it a TLS secret. The memory-only stage receives no reference. Record all candidates, scores, ties and abstentions before validation.
6. Validate candidate roles/directions against saved TLS 1.3 traffic without reference-secret input. Check authenticated decryption and the exact controlled application markers. Treat decoder prerequisites as a separate diagnostic; packet-decoder failure alone does not prove absence of the secret in memory.
7. After selection is sealed, compare each selected traffic secret with the corresponding independent reference. Use zero differences out of 256 bits for a 32-byte secret, or 384 for a 48-byte secret. Never use the TLS 1.2 384-bit denominator automatically.
8. Report independently: presence audit, candidate inclusion, memory-only selection, packet-assisted selection, client-request decryption, server-response decryption, and full two-direction success. Include wrong-secret/one-bit controls. A one-direction result is partial recovery.
9. If development tuning is needed, label that dump as development evidence. Freeze the method before a fresh validation session. Only after this pilot should a bounded repeated-session campaign begin.

## Retention and failure interpretation

Use one development dump at a time; do not start an unattended TLS 1.3 batch. Preserve compact candidate records, private references, PCAPs, timestamps, hashes and pass/fail diagnostics. Delete the large core and disposable profile after the case's analysis is complete and compact evidence is saved, following the user's retention preference.

If extraction fails, first distinguish a wrong capture process/timing, missing captured regions, unsupported memory layout, absent/erased secret, and packet-decoder limitations. Any reference-guided search is only a post-selection diagnostic. It is not independent extraction success and cannot be used to select a candidate in the final validation case.

## Current status

The first development case and one fresh validation case completed under the planned isolation boundary. Both negotiated `TLS_AES_256_GCM_SHA384`, so each directional application traffic secret was 48 bytes (384 bits). Reference-blind extraction produced nine candidates in development and ten in validation. Saved-traffic validation uniquely assigned one client and one server application traffic secret in each case. Independent post-seal verification found exact matches with zero differing bits, decrypted both controlled markers, and confirmed the expected directional failure with one-bit controls.

This demonstrates feasibility in two cases and freezes the method for a bounded 20-session repeatability campaign. It does not establish the campaign outcome, memory-only role selection, recovery of handshake secrets, SHA-256-suite behavior, TLS 1.3 sessions with resumption/0-RTT/KeyUpdate, or general recovery beyond the tested environment.
