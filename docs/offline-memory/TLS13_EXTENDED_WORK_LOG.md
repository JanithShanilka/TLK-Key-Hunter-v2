# TLS 1.3 extended validation work log

## 2026-09-28 — initialization

- Authorized scope: before-response and 30-second delayed capture, actual resumption, bidirectional KeyUpdate, and two overlapping flows. Pilots precede separate 20-case campaigns with 600-second start spacing. No scenario success is inferred from baseline checks.
- Starting commit: `7fa9268b8e769bc129129198e92b236263dcbbc8` on `codex/offline-memory-pilot`.
- The original nested checkout has 84 uncommitted entries. A local status/content-hash snapshot was saved outside Git. No original changes are copied, staged, reset, or committed.
- The managed worktree tool resolved the parent repository and failed on the nested branch. A separate local clone of the nested committed head is used at `../tls13-extended-validation`, branch `codex/tls13-extended-validation`.
- Governing current scope was read from the original working tree, including its uncommitted saved-memory scope revision. Historical live-hook files in the committed head are outside this task and are not evidence.
- Lab inspected before mutation: no active Firefox/capture/campaign processes; approximately 127 GiB available; existing private evidence remains in place.
- Baseline: 20/20 in the existing full-single-connection scenario. Those cases are not new-scenario observations.
- Current verifier only handles a unique full handshake and generation-zero directional roles. Extend it before counting any new scenario.
- Private reference remains root-only; extractor/packet selector run as researcher. Preserve all attempts, script hashes, condition checks, sealed selection, reference equality, marker tests, one-bit controls, and cleanup records. Enforce 8 GiB allocated across cases and at least 20 GiB free.

## Protocol basis and frozen pilot design

RFC 8446 sections 4.2.11, 4.6.3, and 7.2 define negotiated PSK resumption and directional traffic-key updates. OpenSSL `SSL_key_update(..., SSL_KEY_UPDATE_REQUESTED)` requests the peer update; it must be driven by I/O/handshake. A server call alone is not packet evidence of a completed update.

- Timing arms keep the connection open. Before-response capture is bracketed by a server request event and a release gate; delayed capture is at least 30 monotonic seconds after the response event.
- Resumption uses one fresh profile and one server context with tickets enabled, closes the first connection, and requires the second ServerHello PSK extension plus server `session_reused=true`.
- Concurrency holds two distinguishable connections open at once and checks separate TCP flows and client randoms. Each flow has distinct request/response markers.
- KeyUpdate uses a controlled OpenSSL server and a second HTTP request on the same connection after the requested update. Generation-one candidates must directly authenticate generation-one records; deriving an updated key from a recovered generation-zero candidate is not counted as generation-one memory recovery.
- Repeat campaigns may start only after the corresponding pilot satisfies every acceptance criterion. Setup/tool failure stops the run for inspection, with no automatic retry.

## Implementation checkpoint before requested model switch

- User requested Git change markers. Scope checkpoint committed as `0fc1b5c`.
- Added scenario-aware acquisition gates and `extended_server.py`, including a minimal ctypes OpenSSL server-side KeyUpdate harness. This is an **unfinished implementation checkpoint**, not validated scenario support.
- Existing 12 offline unit tests pass; both edited Python modules compile; diff whitespace checks pass. These checks do not validate the new workloads.
- No new pilot or repeat case has been launched; observed new-scenario counts remain zero. No lab files have been changed.
- Pending: extend packet validation and independent verification for per-flow markers, resumption packet evidence, generation-specific KeyUpdate evidence and one-bit controls; add meaningful tests; run each pilot under storage guards; launch only successful scenario campaigns; collect reviewed nonsecret results; push review branch/PR.
- The X-Ray-TLS paper was text-inspected for snapshot context; it does not supply results for these timing arms.
- User requested Daybreak. The current running model cannot be changed by the exposed tools; Codex UI control was explicitly blocked. Work is checkpointed for continuation after the user changes the chat model. No heartbeat created because no campaign has started.

## 2026-09-28 — scenario verifier implementation

- Added reference-free scenario checks that bind server events to observed TCP streams by client port and require separate TLS 1.3 ClientHello randoms.
- Timing checks use monotonic event bounds: the before-response capture must start after the request and finish before the response; delayed capture must start at least 30 seconds after the response.
- Resumption requires server `session_reused=false` then `true`, plus pre-shared-key extension 41 in the second ClientHello and ServerHello. Concurrency requires two distinct ports/randoms whose lifetimes overlap.
- Candidate assignment now reassembles each TCP direction, derives the traffic key and IV from each saved-memory candidate, and directly authenticates the exact controlled marker in a TLS 1.3 record. This supports flow-specific and generation-specific assignment without opening the reference or deriving generation one from a selected generation-zero secret.
- Independent verification checks every target against the root-only reference, authenticates every request/response marker, flips one bit in every reference secret, and applies cross-flow or cross-generation secrets as relevant. KeyUpdate additionally requires decrypted packet evidence of a server `update_requested` message and the client update response.
- The campaign runner now records `setup`, `condition`, `extraction`, and `verification` failures separately; requires 600-second spacing and a 20-GiB reserve; and snapshots every added helper.
- Test suite: 15 tests pass with the bundled cryptographic runtime. The system Python run passes 14 tests and explicitly skips the synthetic AES-GCM test because that local interpreter lacks `cryptography`; the controlled lab Python has `cryptography` 46.0.5.
- No pilot has been launched at this checkpoint. New-scenario observed counts remain zero.

## Retained-traffic compatibility finding

- The manually deployed file hashes matched commit `2f91356` exactly.
- A read-only check against retained case `TLS13-REPEAT-20260928-A-020` found that lab TShark 4.6.4 refuses the intentionally mode-`0400` PCAP path. This is an access/tool compatibility failure, not an extraction result.
- The prior validated code avoided the same behavior by copying the PCAP into an ephemeral temporary directory. The new parser now does likewise for field extraction and TCP reassembly; the copy stays on the controlled host and is automatically removed.
- KeyUpdate packet evidence no longer asks TShark to open a root-only key log. It directly authenticates the server `update_requested` message and client response under the independent generation-zero references after selection is sealed.
- Test suite after repair: 16/16 with the bundled cryptographic runtime; the system interpreter passes the 14 non-cryptographic tests and skips the two AES-GCM checks.

## Pilot observations and resumption amendment

- `TLS13-EXT-BEFORE-PILOT-20260928-A`: 1/1 complete. Capture started 0.227 seconds after the request and ended 7.765 seconds before the response. Ten candidates; one winner for each generation-zero direction; exact reference equality, both controlled markers, all one-bit controls, and cleanup passed.
- `TLS13-EXT-DELAYED-PILOT-20260928-A`: 1/1 complete. Capture started 30.060 seconds after the response. Twelve candidates; one winner per direction; exact equality, markers, controls, and cleanup passed.
- `TLS13-EXT-RESUMPTION-PILOT-20260928-A`: 0/1, condition-stage tool failure. Acquisition completed, but the condition parser stopped on an incomplete third ClientHello. The two completed flows showed full then resumed server state, and the resumed ClientHello/ServerHello both included PSK extension 41; no extraction or verification ran, so the attempt remains unsuccessful rather than being reclassified.
- Amendment before resumption pilot B: bind only completed handshakes to completed server flows. Change the first response to an explicit close-and-redirect to the second controlled path, removing reliance on a browser favicon race. The failed A core/profile remain private on the lab host for inspection.
- Test suite after the amendment: 17/17 with the cryptographic runtime; 15 non-cryptographic tests pass under the system interpreter and two AES-GCM tests are skipped there.
- `TLS13-EXT-RESUMPTION-PILOT-20260928-B`: 0/1 under the four-target rule. The full-then-resumed condition passed and the resumed flow had unique, exact client/server candidates with both markers and controls. The already-closed ticket-establishment flow had no packet-validating candidates in the later memory image. Cleanup completed.
- Amendment before pilot C: treat the first full connection as scenario setup and the second resumed connection as the recovery target. This follows the capture point and avoids requiring secrets for a closed setup flow. The condition still requires full then resumed server state and PSK packet evidence. KeyUpdate is analogously frozen with generation zero as authenticated setup and generation one as the post-update recovery target; generation-zero secrets are applied as wrong-generation controls.
- `TLS13-EXT-RESUMPTION-PILOT-20260928-C`: 1/1 complete under the amended target rule. The server recorded `session_reused=false` then `true`; both second-handshake PSK extensions were present; two completed connections were bound; and ten candidates produced one unique, exact winner for each resumed-flow direction. Both markers, one-bit controls, cross-flow controls, and cleanup passed.

## KeyUpdate pilot observation and label correction

- `TLS13-EXT-KEYUPDATE-PILOT-20260928-A`: 0/1 at verification. The condition stage passed, selected two generation-one targets, and extracted five structurally valid candidates, but the verifier initially found no updated reference labels because this OpenSSL build logs updated secrets as `CLIENT_TRAFFIC_SECRET_N` and `SERVER_TRAFFIC_SECRET_N` rather than numbered `_1` labels.
- A root-only diagnostic established that the `_N` client and server references directly authenticate the controlled post-update request and response. Generation-zero references also directly authenticate the server `update_requested` message and client update response. Neither updated reference occurred literally in the saved core, and none of the five extracted candidates matched either updated reference. The failed attempt remains 0/1; these diagnostics do not reclassify it.
- Before pilot B, the verifier maps OpenSSL's `_N` label to protocol generation one. The workload now uses an explicit same-connection redirect for the second request, removing the browser favicon race. A regression test covers both aliases. Pilot B will determine whether the amended run completes as an explicit recovery failure rather than a verifier-label failure; no repeat campaign is eligible unless a pilot fully passes.
- `TLS13-EXT-KEYUPDATE-PILOT-20260928-B`: 0/1 at verification. The condition passed and ten candidates were extracted. One server generation-one candidate authenticated, but the client generation-one reference was absent. Packet and event ordering showed the redirect response preceded the requested KeyUpdate, so Firefox could issue the redirected request under generation zero. This is a workload-ordering failure, not a complete bidirectional generation-one recovery observation.
- Amendment before pilot C: request and flush the server KeyUpdate before sending the redirect response. The redirect then causes the second controlled request only after Firefox processes the server update and sends its required client update response. Both generation-one labels and both post-update markers remain mandatory.
- `TLS13-EXT-KEYUPDATE-PILOT-20260928-C`: 1/1 complete. Ten candidates produced one unique generation-one winner in each direction. Both references occurred once in the core and matched exactly; both controlled post-update markers authenticated; one-bit and generation-zero controls were rejected; the server requested a peer update and the client update response authenticated directly from packet records. Raw core and disposable profile cleanup completed.
- `TLS13-EXT-CONCURRENCY-PILOT-20260928-A`: 1/1 complete. Two overlapping connections with distinct client randoms produced four unique exact winners from sixteen candidates. Every request/response marker authenticated; all one-bit and four cross-flow controls were rejected; and raw core/profile cleanup completed.

## 2026-09-29 — frozen repeat campaigns complete

- Five separate 20-case campaigns completed with starts spaced by at least 600 seconds: before-response 20/20, 30-second delayed capture 20/20, resumption 20/20, KeyUpdate generation one 20/20, and two-flow concurrency 20/20. Aggregate observed result: 100/100.
- All 100 cases passed their scenario condition, unique packet-authenticated assignment, exact reference equality, controlled marker checks, applicable one-bit/cross-flow/cross-generation controls, and raw core/profile cleanup.
- Candidate counts ranged from 9 to 20 with median 10. Case execution time ranged from 42.194 to 105.939 seconds with median 50.541 seconds, excluding inter-case spacing.
- All five campaign manifests record identical hashes for the ten frozen acquisition, extraction, packet, verification, and runner scripts. No setup, condition, extraction, verification, storage, or cleanup failure occurred in the repeat campaigns.
- Only `manifest.json`, `summary.json`, `runs.json`, and `runs.csv` were copied into `docs/offline-memory/campaigns/TLS13-EXT-*`. References, candidate values, cores, profiles, PCAPs, and private logs remain on the controlled host.
- Interpretation is limited to the controlled Firefox/host builds, localhost workload, `TLS_AES_256_GCM_SHA384`, selected timing and state conditions, and privileged saved-memory acquisition. This is evidence of post-acquisition secret recovery in those conditions, not a network-only attack or a general TLS 1.3 break.
- Final nonsecret report: `docs/offline-memory/TLS13_EXTENDED_RESULTS.md`.
