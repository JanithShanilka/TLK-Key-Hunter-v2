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
