# Saved-memory experiment work log

This is the running process log for the Firefox saved-memory research workflow. Record actions and observed results here as work proceeds; do not treat planned steps as completed experiments.

Protocol: [SAVED_MEMORY_EXPERIMENT.md](SAVED_MEMORY_EXPERIMENT.md).

## 2026-09-27 — Lab preparation (Asia/Colombo)

- User confirmed the lab is accessible through the Codex terminal and requested installation of the memory-dump tooling plus an ongoing Markdown record.
- Host: `root@<private-lab-host>`, hostname `ubuntu-MIS3205`, Linux x86-64.
- Prior read-only check found `/usr/bin/tshark`, `/home/researcher/research/TLSKeyHunter`, and `/opt/tlskeyhunter/firefox-136.0.2-pristine`.
- Prior check found neither `gdb` nor `gcore` in PATH. Available disk space was approximately 128 GB.
- Installation started at 2026-09-26T20:32:36Z (UTC): checking package availability before installing Ubuntu's `gdb` package, which supplies `gcore`.
- Status: installation completed and verified. No Firefox memory capture or offline recovery experiment has run yet in this workflow.

### Planned commands

```sh
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends gdb
gdb --version
command -v gcore
gcore --help
```

Installation will not include a general system upgrade or reboot. Verify the resulting package version and both executable paths, then append the outcome below.

### Installation outcome

- `apt-get update` completed successfully.
- Installed `gdb` version `17.1-2ubuntu1` and six dependencies from the configured Ubuntu mirror: `libbabeltrace1`, `libdebuginfod-common`, `libdebuginfod1t64`, `libipt2`, `libsource-highlight-common`, `libsource-highlight4t64`.
- APT reported 7 new packages, 0 upgraded, 0 removed, and approximately 13.9 MB additional disk usage. Installation exited with status 0.
- Verified at 2026-09-26T20:33:23Z: `/usr/bin/gdb`, `/usr/bin/gcore`, `GNU gdb (Ubuntu 17.1-2ubuntu1) 17.1`; `gcore --help` completed successfully.
- No general upgrade or reboot was performed. Package tooling reported deferred service restarts.
- Next: inspect the existing lab and perform a separate controlled capture pilot without the live secret-export hook. Tool installation is not evidence of secret recovery.

### Read-only lab readiness check

- Research checkout `/home/researcher/research/TLSKeyHunter` is on `codex/v2-gap-closure`; `git status --short` returned no changes.
- No `AGENTS.md` files were found under the checked research parent directory.
- Confirmed `/home/researcher/.venv/bin/python`, `/usr/bin/Xvfb`, `/usr/bin/tcpdump`, and `/usr/bin/certutil`.
- Inspected the existing server and process-selection helpers. The current baseline server closes its connection after sending the response, so the saved-memory pilot needs an explicit capture window while the connection is still active.
- The existing Firefox helper distinguishes the parent browser from its socket process. The pilot must record the process actually responsible for the controlled connection rather than assume that the parent holds the secret.
- The existing Firefox preferences include a socket-sandbox override. This readiness check did not change preferences or disable any sandbox; a new pilot must record its own configuration rather than silently inherit that override.
- No Firefox process was started, no memory dump was captured, and no TLS secret was extracted during installation/readiness verification. Existing experiment data remains unchanged.

## Controlled memory-capture pilot — started

- User requested continuation after installation.
- Created local branch `codex/offline-memory-pilot` in `TLK-Key-Hunter-v2-publish`.
- Added `lab/offline_memory/capture_firefox.py`; Python syntax check passed.
- Created a separate remote pilot workspace `/home/researcher/research/TLSKeyHunter-memory-pilot`; the historical research checkout is not edited.
- Planned first case: `FIREFOX-TLS12-CORE-PILOT-001`. Fresh researcher-owned Firefox profile, localhost port 18443, TLS 1.2 constrained to ECDHE-RSA-AES128-GCM-SHA256, streaming response held open during capture.
- Capture uses GDB core generation with startup scripts/auto-loading disabled. No Frida hook or target key logging is used. Socket-process ownership is checked with `ss` before capture.
- Independent server key reference remains under `/root/tlkh-memory-reference/`, outside the normal researcher's file access. Capture code does not read that reference.
- This is exploratory development, not a final statistical sample. Outcome pending.

### Development cases 001–003

- Case 001 timed out before the HTTP request. Server log recorded `SSLV3_ALERT_BAD_CERTIFICATE`; Firefox also logged sandbox/seccomp failures and an inherited root runtime-directory warning. No usable core was captured. Case preserved.
- Case 002 used a leaf certificate with `CA:FALSE` and a researcher-owned runtime directory. It again failed before the request with a certificate alert. `certutil -V` validated the profile certificate, but Firefox still rejected the connection. Case preserved.
- Case 003 changes to a separate short-lived local CA and a CA-signed localhost leaf, trusting the CA in the disposable Firefox profile. Certificate validation remains enabled. Outcome pending.
- Added an ELF64 core reader, an exploratory SECItem-shaped 48-byte candidate enumerator/ranker, and a separate reference verifier. Five synthetic tests passed: virtual address access, omitted-page rejection, truncated core rejection, duplicate-candidate grouping, ambiguous-score abstention, and zero/invalid candidate rejection (some checks share a test).
- The new method is explicitly not the original live argument ranker D. It reuses single-snapshot readability/length/entropy/zero-count ideas and does not pretend to have call history.
- The verifier distinguishes reference-guided literal presence, blind candidate selection, and decryption with the selected candidate. Reference-only sanity decryption cannot count as extractor success.

### Case 004 — explicitly approved compatibility condition

- Case 003 failed with `TLSV1_ALERT_UNKNOWN_CA` before the controlled request, alongside Firefox sandbox/seccomp crashes. No core captured; preserved as failed setup.
- User explicitly approved disabling only `security.sandbox.socket.process.level` in the disposable lab profile. This is the same scope of exception used by the earlier lab runner; certificate validation remains enabled and system-wide settings are unchanged.
- Added an explicit `--lab-disable-socket-sandbox` flag, default off, recorded in acquisition metadata. Case 004 uses this flag. The capture script now also checks that the selected process has no `SSLKEYLOGFILE` environment entry or Frida mapping.
- Added cross-segment memory-search coverage: all 6 synthetic offline tests pass.
- All setup failures remain in the development record. They must not be silently omitted from any future all-attempt accounting.

### Certificate compatibility and case 007

- Cases 004, 005 and 006 failed before the controlled HTTP request with certificate alerts; no usable cores were acquired. Case 005 matched both CA and leaf trust entries; case 006 added the original runner's process-scoped `MOZ_DISABLE_SOCKET_PROCESS_SANDBOX=1` switch within the already-approved socket exception.
- OpenSSL hostname/chain verification and NSS `certutil` validation succeeded independently. Root cause of Firefox's trust rejection remains unresolved; do not describe it as a proven certificate-generation defect.
- Inspection found the historical runner also used WebDriver BiDi `acceptInsecureCerts=true`. User initially required validation, then explicitly requested using `acceptInsecureCerts`. The later instruction authorizes the temporary localhost automation-session exception.
- Case 007 uses an explicit, default-off `--lab-accept-insecure-certs` flag alongside the approved socket exception. TLS 1.2 encryption remains active; certificate-authentication behavior is no longer part of this pilot's claim.
- User requested minimal scope. Remaining work is limited to capture, offline ranking, independent comparison, decryption, and this log; no unrelated features or target expansion.

### Connection-owner correction and case 008

- Case 007 completed the controlled TLS handshake and request: TLSv1.2, ECDHE-RSA-AES128-GCM-SHA256. It stopped before capture because the nominal Firefox socket process did not own the connection.
- Inspection of the earlier runner showed it observed a socket process but attached its extraction hook to the parent browser. This reinforces the need to verify actual connection ownership rather than infer it from a process name.
- The capture step now obtains `ss -tnp` ownership, requires exactly one matching parent/socket Firefox PID, verifies NSS modules and absence of key logging/Frida in that PID, and records the selected PID. Case 008 tests this correction with a fresh connection and profile.

### Case 008 capture, first blind scan, and storage

- Capture succeeded with a 9,184,771,680-byte apparent ELF core. SHA-256: `53ba3462d961e973935ce866a4ae33bbc71ff57ed1a30726eb9542549cfc89c7`.
- Actual allocated disk usage is only **281 MB** because the core is sparse. All pilot case directories together occupy **625 MB**; approximately 127 GB remains free.
- User requested storage-conscious operation. Keep only this one raw development core for now; do not start a multi-dump campaign or transfer raw memory to GitHub/local storage. Preserve sparse allocation and avoid unnecessary duplicate copies. Compression is available if archival becomes necessary.
- Confirmed the normal researcher account could not read the root-only server reference before invoking the scanner under that account.
- Blind single-snapshot scan completed in 19.46 seconds over 918 captured segments: 335 plausible structures, 98 distinct eligible candidate values, 68 tied at the highest score.
- Selection outcome: **ambiguous**, no selected candidate. This is not successful extraction. Sealed candidate-file hash: `348eb291c37c9b796b8c12ed5f4d5736d811d722d6e9faccdfc8419e2469b4b3`.
- Only after that output was sealed was the root-side independent verifier started. Reference presence, candidate recall and decryption checks are pending.

### Case 008 reference verification and minimal discovery revision

- The independent verifier found the exact reference master secret once in captured memory, but outside the first scanner's 98 candidates. Baseline offline recovery therefore failed. Reference-only decryption recovered both controlled markers; a one-bit-corrupted reference recovered neither.
- TShark's capability drop prevented access through the researcher's private directory. Verification now makes a temporary private copy of only the small PCAP/key inputs, removed automatically; it never copies the core. GDB reported unreadable regions, so the dump is not claimed to contain every mapped byte.
- Testing a separate PKCS#11 CKA_VALUE layout (type 0x11, pointer, full-width length 48) on the same development core. NSS softoken uses CKA_VALUE attributes; the initial SECItem type filter excluded 0x11. This is a source-based development hypothesis, not a validated recovery claim. Baseline output is preserved.
- Sources: https://searchfox.org/mozilla-central/source/security/nss/lib/softoken/pkcs11c.c and https://github.com/mozilla/pkcs11-bindings/blob/main/pkcs11t.h .
- Seven synthetic tests passed, including wrong attribute type and oversized 64-bit length rejection. Any improvement on this already-audited core remains development evidence and requires a fresh held-out case before an independent validation claim.
- Storage policy: reuse case 008 for development; no raw core transfers, duplicate cores, or batch captures. Keep small non-secret summaries locally. Review actual allocated space before any necessary fresh validation capture.

### Case 008 CKA_VALUE result

- Reference-blind CKA_VALUE enumeration took 20.70 seconds and returned five distinct candidates, all score 75. Post-seal verification confirmed the exact reference is in this set, tied first with four other candidates. Memory-only selection still abstains.
- Adding only a separate packet-validation step: try each sealed candidate against the existing single-connection PCAP and select only if exactly one yields parsed HTTP request and response. This step uses the public ClientHello random from PCAP and has no reference-secret input. Preserve both the memory-only and packet-assisted outcomes; this does not improve the memory ranker's discrimination.

### Packet-assisted development outcome and prospective validation

- The researcher could read the PCAP directly with Python, but TShark denied the same path. A researcher-owned private temporary PCAP copy allowed validation; the precise confinement cause is not established. This supersedes the earlier capability-drop explanation, which was a hypothesis. No sandbox/security settings were changed for TShark.
- Exactly one of the five sealed CKA_VALUE candidates yielded both parsed HTTP request and response in the existing PCAP, without reading the reference. Memory-only ranking still has five ties. Independent exact-match verification is pending.
- Prospective case 009: freeze the current CKA_VALUE scanner and packet-validation rule before acquisition; capture one fresh connection, run as researcher with no reference access, seal selection, then verify as root. No tuning on case 009 before reporting its result. This single held-out trial is necessary to separate development from new-session validation; it is not a reliability campaign or a general percentage estimate.
- Retention bound: one development core plus one validation core, kept sparse remotely. Check allocated storage before starting; no bulk experiment and no raw-memory download.

### Frozen method and fresh case 009

- Case 008 packet-assisted verification succeeded: selected candidate exactly equals the independent 48-byte master secret (Hamming distance 0); both controlled markers decrypt; one-bit negative control fails. This remains development evidence.
- Method hashes recorded before case 009: rank_core.py `cdee1797ce5c48493017b51517a4ab51c254f98a599aa5268a57e27deaeddd1f`; validate_candidates.py `e321696de87f8d1473ec9b369c5725b5f5f7675f38650661ec24dfe79709432b`; capture_firefox.py `ac5060ff9b60362c5f88ef7ef554161843d55e62ea3785b3d18d1058b9eebca1`; verify_core.py `9d419922ca434a3b3c03a558feaa91a5349c7480024cefbefd2f00a55449830d`.
- Fresh case 009 captured successfully with apparent size 9,191,625,816 bytes and SHA-256 `daa09aa02b9c50f560cf5f858b2a73eb8a9ca9af02a5df0eb02d9c126a74ea35`. It uses the same previously authorized disposable-profile conditions. Ranking and packet validation run under researcher after confirming no reference read access, before reference verification.

### Fresh case 009 outcome and stopping point

- Frozen CKA_VALUE scan completed in 19.58 seconds: five distinct candidates, all tied at score 75. Exactly one passed reference-free packet validation. Independent post-seal verification confirmed an exact 48-byte secret match (0 differing bits) and both controlled request/response markers decrypted. The one-bit negative control failed.
- Held-out observed outcomes: candidate inclusion 1/1; unique memory-only selection 0/1 (abstained on tie); packet-assisted exact recovery plus decryption 1/1. One held-out case is insufficient for a general success-rate estimate. Development case 008 is reported separately, and setup cases 001–007 remain in the record. TLS 1.3 is untested by this offline method. Score 75 is a ranking score, not 75% correctness.
- Final pilot case directories occupy 940 MiB. Exactly two raw cores are intended retained (development 008 and validation 009); no additional captures scheduled. Only small non-secret verification summaries were downloaded locally. Ordinary copies may expand the apparent 9.2 GB sparse cores, so raw-memory transfers remain avoided.
- Seven synthetic tests passed; all offline Python scripts compile. Actual lab integration demonstrated packet-assisted recovery on development and fresh validation cases. No broad target/version claim follows.

### Private visible-secret evidence view

- User explicitly requested to see the live-session secret and each offline candidate trial. Created a private HTML view of existing case 009 evidence and copied only that small page locally, with file mode 0600. This page contains actual lab secret values and must remain private; no raw core was transferred and nothing was published.
- The page identifies the independent server reference as recorded during the completed live session, not a currently running live feed. Five candidates were tried: candidate 1 in the sealed file order passed; candidates 2–5 failed to recover the required HTTP pair. All five memory scores tied. Exact equality and bit-difference diagnostics were added only after independent selection.
- No new capture, new dump, or extraction rerun. Existing 008/009 evidence and frozen validation method remain unchanged. Page checks confirmed five trial rows, one PASS and four FAIL.

## 2026-09-28 — Bounded repeatability campaign

- User selected 20 fresh sessions ten minutes apart and explicitly requested deletion of large offline files after each run. Added a sequential campaign runner with immutable method snapshots, UTC timestamps, stage logs, per-case JSON, aggregate JSON/CSV, failure accounting and disk guards (8 GiB allocated pilot-case budget, 20 GiB minimum free).
- Each completed verification is saved before deleting the raw core and disposable profile/runtime. Small packet captures, candidate records, isolated references, hashes and logs remain private. Reanalysis with a different extractor is impossible after dump deletion. Unexpected tool/setup failures stop and preserve incomplete evidence for inspection.
- All 10 tests passed (7 memory tests, 3 campaign tests). Capture handles campaign termination by cleaning up its owned processes. A service manager keeps the bounded runner alive independently of SSH.
- First attempt TLS12-REPEAT-20260928-A-001 captured but failed to start ranking because the frozen script directory inherited restrictive umask permissions. Campaign A stopped. Its original failure remains in the denominator and was not overwritten.
- Corrected directory traversal permissions without changing extraction rules. Reanalyzed the same dump: five tied candidates, one packet pass, exact reference match, both markers decrypted, one-bit negative control failed. This post-repair result is separate in A/post-repair-analysis.json. No replacement capture was made. The first attempt's dump and disposable profile were deleted only after verified results were saved.
- Continuation TLS12-REPEAT-20260928-B runs the remaining 19 sessions with ten-minute start-to-start spacing, including an initial delay from the first attempt. Service: tlkh-repeat-20260928-b. Total requested capture count remains 20 across A and B. Initial extraction rules remain fixed; progress is not a final success-rate claim.
- A 15-minute thread follow-up checks for completion or actionable failure, stays quiet on ordinary progress, and will collect only non-secret summaries and update the log/Git after completion.

## Repeatability campaign completion

- Remote service is inactive with campaign B state `completed`; 19/19 continuation sessions recovered exact reference secrets and decrypted both markers. Original A-001 ranking-launch permission failure remains intact; its separate post-repair reanalysis succeeded. Total captures: 20; initial unattended success: 19/20; eventual recovery including repair: 20/20. These are fixed-lab observed rates, not general reliability claims.
- Memory-only unique selection remained 0/19 in B due to ties. Candidate sizes were five in 15 sessions and four in four sessions: 91 candidate checks, 19 packet passes, 72 failed checks. All 19 one-bit negative controls failed to decrypt both markers.
- All 19 B result rows and A's repair record confirm raw-core/profile deletion. Final allocated pilot-case bytes: 989,298,688. Only approved non-secret manifests, summaries, runs JSON/CSV and the separate repair summary were downloaded.
- Capture/extractor/verifier hashes match between A and B; only the orchestration runner changed. Completion analysis is in REPEATABILITY_RESULTS.md. Follow-up automation `check-tls-repeatability-campaign` was paused after completion; no further runs were started.

### Permanent live-session report and TLS 1.3 next-step plan

- User emphasized preserving Live-session secrets and offline recovery. Saved a versioned finding document with all 20 session outcomes and a redacted HTML archival copy of the private report. All 136 displayed 48-byte secret values (references, winners and candidates) were redacted from the Git copy. The full-key report remains outside Git.
- Preserved exact wording: every tested TLS 1.2 session was eventually recovered; 19 completed automatically and one required permissions repair and same-dump reanalysis. Memory-only ambiguity remains explicit.
- Saved a separate RFC-grounded TLS 1.3 pilot plan covering directional traffic secrets, hash-dependent lengths, independent references, packet validation, failure diagnostics and bounded retention. No TLS 1.3 capture was started in this documentation step.

### TLS 1.3 development and fresh validation

- Added a separate TLS 1.3 capture mode, structured 32/48-byte candidate discovery, directional saved-PCAP validation, independent verifier and bounded campaign runner. TLS 1.2 defaults and records remain unchanged.
- Development case `FIREFOX-TLS13-CORE-DEV-001` negotiated `TLS_AES_256_GCM_SHA384` and produced nine candidates. Without reference access, packet validation selected exactly one client and one server application traffic secret and decrypted both markers. Post-seal verification confirmed both exact matches with zero differing bits out of 384.
- Froze the capture, reader, ranker, validator and verifier hashes before `FIREFOX-TLS13-CORE-VALIDATION-001`. The fresh case negotiated the same suite and produced ten candidates. It independently produced one client winner and one server winner; both matched exactly and decrypted request and response.
- Directional one-bit controls behaved as expected in both cases: corrupting the client secret prevented request recovery only, while corrupting the server secret prevented response recovery only. References remained root-only until selection was sealed.
- Memory-only candidate discovery does not assign traffic-secret roles. Packet validation remains part of the complete recovery method. The two successful cases justify a bounded 20-session campaign; they are not themselves a repeatability rate.

### TLS 1.3 repeatability campaign completion

- Campaign `TLS13-REPEAT-20260928-A` completed without interruption: 20/20 fresh sessions achieved complete offline recovery. Every session uniquely selected one client and one server application traffic secret through saved-PCAP validation, matched both independent references exactly with zero differences out of 384 bits, and decrypted both controlled HTTP markers.
- All sessions negotiated `TLS_AES_256_GCM_SHA384`. Four sessions produced nine candidates and sixteen produced ten, for 196 candidates total. Memory-only discovery still did not assign directional roles.
- All 20 directional negative controls behaved as expected: changing the client secret blocked request recovery only; changing the server secret blocked response recovery only. Median end-to-end session time was 51.01 seconds.
- Every result row records deletion of its raw core and disposable profile/runtime after durable result saving. Final allocated storage across retained pilot cases was 995,569,664 bytes. Only non-secret summary, manifest and JSON/CSV records were downloaded and versioned.
- Detailed conclusions and limits are recorded in `TLS13_REPEATABILITY_RESULTS.md`. The periodic monitor was deleted after completion and no further capture was launched.
