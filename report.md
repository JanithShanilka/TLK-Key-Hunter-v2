# TLSKeyHunter Controlled-Lab Implementation and Experiment Report

**Project:** Improving the Robustness of Static-to-Dynamic TLS Key Extraction  
**Repository:** `enigmazero-net/TLSKeyHunter`  
**Laboratory host:** `89.167.33.8`  
**Remote repository:** `/home/researcher/research/TLSKeyHunter`  
**Experiment branch:** `codex/plan-v2-completion`  
**Frozen source commit:** `e0104374f113fd00a8f03bcadce46573b71e5951`  
**Frozen configuration time:** `2026-07-29T18:33:27Z`  
**Report prepared:** `2026-07-30`  
**Scope:** Authorized university-controlled localhost TLS experiments

---

## 1. Purpose of this document

This document provides a complete technical and operational view of the work performed for the TLSKeyHunter research plan. It is written so that a student can understand:

- what TLSKeyHunter is trying to discover;
- how static analysis and dynamic instrumentation fit together;
- how `arg_ranker` works;
- how the controlled wolfSSL and Firefox/NSS experiments work;
- how an extracted candidate is proven correct;
- what failed during development;
- how each failure was corrected;
- what evidence was generated;
- how to inspect and verify that evidence;
- how to run a new case or campaign;
- what remains incomplete and must not be claimed as completed.

This report does not contain raw TLS secrets. Secret-bearing files remain on the controlled lab machine with owner-only permissions.

### Navigation

- [Executive summary](#2-executive-summary)
- [Core concepts](#3-core-concepts)
- [Implemented components](#4-implemented-components)
- [How `arg_ranker` works](#5-how-arg_ranker-works)
- [Controlled wolfSSL baseline](#6-controlled-wolfssl-baseline)
- [Firefox/NSS architecture](#7-firefoxnss-tls-13-architecture)
- [Acceptance and evidence](#9-acceptance-and-exclusion-rules)
- [Failures and solutions](#11-what-did-not-work-and-how-it-was-solved)
- [Generated results](#12-results-generated)
- [Commands for new sessions](#17-running-one-firefoxnss-session)
- [Viewing and verifying results](#21-viewing-and-verifying-results)
- [Troubleshooting](#22-troubleshooting-guide)
- [Completion matrix](#24-completion-matrix-against-the-plan)

---

## 2. Executive summary

The implementation produced three major outcomes:

1. A tested JavaScript argument-ranking module was added for selecting likely TLS-related function arguments instead of blindly trusting hardcoded argument positions.
2. Controlled wolfSSL TLS 1.2 and TLS 1.3 baseline cases were successfully captured, matched against independent ground truth, and decrypted.
3. A reproducible Firefox 136.0.2/NSS TLS 1.3 measurement system was built and used for a final campaign of 90 sessions.

The final Firefox/NSS TLS 1.3 result was:

| Measurement | Result |
|---|---:|
| Runs | 3 |
| Sessions per run | 30 |
| Total eligible sessions | 90 |
| Fully recovered sessions | 90 |
| Session recovery coverage | 100% |
| Run 1 | 30/30 |
| Run 2 | 30/30 |
| Run 3 | 30/30 |
| Frida candidate events | 900 |
| Verified candidate groups | 900 |
| Runner failures | 0 |
| 95% Wilson interval | 95.91%–100% |
| Per-case manifests checked | 90 |
| Per-case manifest failures | 0 |

All eight final negative controls passed. The positive sanity check recovered both the exact controlled request path and the exact response marker.

The final Firefox result was collected in **measurement mode**, with no Firefox `SSLKEYLOGFILE` ground truth. Candidate correctness was established by authenticated TShark decryption and recovery of case-specific request and response markers.

### Important completeness boundary

The following work is **not complete**:

- the Firefox/NSS TLS 1.2 implementation;
- the final Firefox/NSS TLS 1.2 experiment of 3 × 30 sessions;
- a live multi-library `arg_ranker` ablation campaign;
- a measured analyst-effort reduction study;
- final live GUI/VNC screen recordings;
- a frozen, detected Ghidra installation in the final environment.

The accepted wolfSSL TLS 1.2 baseline proves that the controlled baseline method works for TLS 1.2. It is not a substitute for a Firefox/NSS TLS 1.2 campaign.

---

## 3. Core concepts

### 3.1 What problem is being solved?

TLS applications derive encryption secrets inside process memory. If a researcher can identify the relevant derivation function and safely observe the correct arguments, those secrets can be represented in NSS key-log format and used to decrypt a captured session.

The challenge is that:

- function names may be stripped;
- addresses change between builds;
- calling conventions differ;
- argument positions differ between functions and versions;
- many readable memory regions are not cryptographic secrets;
- a plausible-looking value is not proof of correctness.

TLSKeyHunter addresses the static part of the problem by identifying key-derivation fingerprints. Frida performs the dynamic part by attaching to the running process and observing the identified function.

```text
Target TLS binary
       |
       v
Static analysis with TLSKeyHunter/Ghidra
       |
       +--> derivation function
       +--> call-site information
       +--> byte-pattern fingerprint
       |
       v
Version-specific Frida hook
       |
       +--> attach to the authorized target process
       +--> locate the fingerprint in memory
       +--> observe candidate arguments/results
       |
       v
Candidate NSS key-log entries
       |
       v
PCAP + ClientHello random + TShark
       |
       v
Authenticated HTTP decryption
       |
       +--> exact request path found?
       +--> exact response marker and nonce found?
       |
       v
Accepted result or Unverified result
```

### 3.2 What counts as a correct secret?

A TLS secret is never graded by similarity.

```text
Exact equality with independent development ground truth
                            OR
Authenticated decryption of the intended TLS stream,
including the exact controlled request and response marker
                            =
                         Correct

One-bit difference, plausible entropy, correct length, or
encrypted application data without authenticated decryption
                            =
                  Incorrect or unverified
```

Entropy and length are useful for ranking candidates. They are not proof.

### 3.3 Static identification versus dynamic extraction

The experiment has two related but different layers:

| Layer | Purpose | Main artifacts |
|---|---|---|
| Static identification | Find likely TLS derivation functions and stable fingerprints | `TLSKeyHunter.java`, Ghidra workflow, byte pattern |
| Dynamic extraction | Observe the function in a running application | Frida JavaScript hooks |
| Candidate selection | Rank or select possible arguments | `arg_ranker.js`, version-specific ABI knowledge |
| Functional validation | Prove the candidate decrypts the intended connection | PCAP, TShark, request path, response marker |
| Evidence control | Make the experiment reproducible and auditable | hashes, Build IDs, manifests, frozen metadata |

The final Firefox experiment reused a fingerprint originally identified through static analysis, but it did not rerun Ghidra for every session.

---

## 4. Implemented components

### 4.1 Main implementation files

| File | Role |
|---|---|
| `tlsKeyExtraction/arg_ranker.js` | Ranks secret, label, random, integer, and structure candidates |
| `tlsKeyExtraction/openssl_key_dump_linux_x86_64.js` | OpenSSL hook integrated with the ranker and no-candidate behavior |
| `tlsKeyExtraction/wolfssl_key_dump_linux_x86_64.js` | wolfSSL hook with corrected TLS 1.3 secret length handling |
| `tests/test_arg_ranker.js` | Eight deterministic ranker unit tests |
| `tests/run_arg_ranker_ablation.js` | Four-configuration synthetic fixture ablation |
| `lab/baseline/run_wolfssl_baseline.py` | One-case wolfSSL TLS 1.2 or TLS 1.3 baseline runner |
| `lab/baseline/tls_server.py` | Controlled TLS baseline server |
| `lab/baseline/wolfssl_workload.js` | Frida-controlled wolfSSL workload support |
| `lab/firefox/nss_firefox_136.0.2.js` | Version-specific Firefox/NSS TLS 1.3 hook |
| `lab/firefox/firefox_nss_fingerprints.json` | Allowed hashes, Build IDs, pattern, and required match count |
| `lab/firefox/phase18a_firefox_nss_runner.py` | Single Firefox TLS 1.3 evidence-producing runner |
| `lab/firefox/run_campaign.py` | Repeats independent cases and aggregates results |
| `lab/firefox/run_negative_controls.py` | Runs the eight required negative controls |
| `lab/firefox/create_fixed_certificate.py` | Creates a repeatable localhost CA and leaf certificate bundle |
| `lab/freeze_experiment.py` | Freezes versions, hashes, policy, methodology, and reference evidence |

### 4.2 Git history for this implementation

| Commit | Main contribution |
|---|---|
| `ecd9171c` | Ranked extraction, tests, ablation fixture, wolfSSL baselines, Firefox runner, controls |
| `53e82d24` | Ground-truth-free Firefox measurement mode |
| `4df7480e` | Frozen reproducible Firefox inputs |
| `e0104374` | Repeatable Firefox campaign driver |

The final campaign records the full commit:

```text
e0104374f113fd00a8f03bcadce46573b71e5951
```

---

## 5. How `arg_ranker` works

### 5.1 Why a ranker was needed

An original hook may use an expression such as:

```javascript
const secret = args[9];
```

This works only while the target function, build, architecture, and compiler preserve that argument layout. A changed build may move the secret to a different argument. Worse, a readable but incorrect argument may produce plausible-looking bytes.

The ranker examines multiple arguments and returns candidates only when they pass a confidence threshold.

```text
Function arguments args[0] ... args[11]
                 |
                 v
        Pointer/readability checks
                 |
                 v
     Expected type/length checks
                 |
                 +--> secret bytes: entropy and zero count
                 +--> label: known TLS label mapping
                 +--> integer: expected length value
                 +--> structure: readable header
                 +--> random: 32-byte random-like value
                 |
                 v
   Preferred-position and call-history scoring
                 |
                 v
        Sort by descending score
                 |
                 v
 score >= threshold? ---- no ----> return no candidate
          |
         yes
          |
          v
      candidate list
```

### 5.2 Frozen thresholds

| Candidate type | Minimum score |
|---|---:|
| Secret | 65 |
| Label | 60 |
| Client random | 50 |
| Integer | 50 |
| Structure | 50 |

### 5.3 Main scoring behavior

For a secret candidate:

- readable memory of an expected length begins at score 40;
- entropy of at least 4.0 adds 25;
- a low zero-byte count adds 10;
- a preferred argument index adds 30;
- consistency with the previous selection at the same call site adds 10.

The exact features depend on candidate type. A known TLS label, for example, receives a strong label-specific score.

### 5.4 “No candidate” is a required result

If no candidate meets the minimum score, the ranker returns an empty list. The OpenSSL hook then skips extraction.

This behavior is intentional:

```text
Low confidence
     |
     v
No candidate
     |
     v
No key-log output
     |
     v
Session is recorded as no-candidate/unverified
```

The previous hardcoded fallback was disabled because silently using the old `args[index]` after the ranker rejected all candidates would defeat the purpose of confidence gating.

### 5.5 Build requirements

`arg_ranker.js` does not have a separate compilation step. Frida loads JavaScript at runtime. The required checks are syntax validation and tests:

```bash
cd /home/researcher/research/TLSKeyHunter

node --check tlsKeyExtraction/arg_ranker.js
node tests/test_arg_ranker.js
node tests/run_arg_ranker_ablation.js research_notes/arg_ranker_ablation-new.json
```

Expected test ending:

```text
8 arg_ranker tests passed
```

### 5.6 Ablation results

The deterministic fixture contains 12 possible true argument positions and 10 calls per group, producing 120 observations per configuration.

| Configuration | Correct | Total | Accuracy |
|---|---:|---:|---:|
| A: hardcoded argument 9 | 10 | 120 | 8.33% |
| B: length only | 10 | 120 | 8.33% |
| C: length + entropy | 21 | 120 | 17.50% |
| D: length + entropy + consistency | 120 | 120 | 100.00% |

Interpretation:

- length alone cannot separate equally sized candidates;
- entropy helps on the first call when decoys are zero-filled;
- consistency identifies the stable argument after the first call;
- this is a **synthetic deterministic fixture**, not a live multi-library benchmark.

The result supports the ranker logic, but it must not be reported as 100% live extraction accuracy across TLS libraries.

### 5.7 Where the ranker is and is not used

- The OpenSSL hook uses `ArgRanker` for labels, structures, secrets, client randoms, and integer lengths.
- The wolfSSL hook fix in this work focused on correct TLS 1.3 length selection and structured output.
- The final Firefox 136.0.2 hook uses a fingerprint-gated, known function signature and fixed NSS argument positions.

Therefore, the 90-session Firefox result validates the Firefox/NSS extraction and verification pipeline. It is not a 90-session test of dynamic argument discovery by `arg_ranker`.

---

## 6. Controlled wolfSSL baseline

### 6.1 Purpose

The baseline proves the complete chain with an easier supported library before moving to Firefox:

```text
Frida candidate
       =
key-export client ground truth
       =
key-log entry that decrypts the captured session
```

### 6.2 What the baseline runner does

For one protocol, the runner:

1. creates a unique case directory;
2. records environment and source hashes;
3. generates a short-lived localhost certificate;
4. starts a protocol-pinned TLS server;
5. starts loopback capture;
6. runs a wolfSSL key-export client under the Frida hook;
7. extracts candidate and ground-truth lines;
8. requires exact equality;
9. uses the verified entry with TShark;
10. checks the exact request and response marker;
11. writes metrics, reports, and a SHA-256 manifest.

### 6.3 Accepted baseline results

| Case | Protocol | Ground-truth labels | Verified candidates | Result |
|---|---|---:|---:|---|
| `BASELINE-WOLFSSL-TLS12-014` | TLS 1.2 | 1 | 1 | Accepted |
| `BASELINE-WOLFSSL-TLS13-001` | TLS 1.3 | 4 | 4 | Accepted |

Both cases recorded:

- a complete handshake;
- ClientHello frame 4;
- ServerHello frame 6;
- a Frida candidate event;
- exact ground-truth equality;
- successful TShark decryption;
- exact request-path recovery;
- exact response-marker recovery.

The stored Frida CLI exit value is not used alone as the acceptance decision. The instrumented client can end in a way that gives the wrapper a nonzero Frida exit after the evidence has already been captured. Acceptance requires the explicit verification checks.

### 6.4 wolfSSL TLS 1.3 length correction

The original hook attempted to infer secret length by scanning random key bytes until a zero byte. Cryptographic bytes may naturally contain zero, so that method is invalid.

The corrected hook reads wolfSSL’s hash identifier:

```text
hash identifier 4 --> SHA-256 --> 32-byte secret
hash identifier 5 --> SHA-384 --> 48-byte secret
anything else    --> reject unsupported length
```

It also tags key lines with `[TLSKH_KEY]` so the parser can distinguish structured key output from diagnostics.

---

## 7. Firefox/NSS TLS 1.3 architecture

### 7.1 Frozen target

| Artifact | Frozen value |
|---|---|
| Firefox | Mozilla Firefox 136.0.2 |
| Firefox path | `/opt/tlskeyhunter/firefox-136.0.2-pristine/firefox` |
| `libssl3.so` SHA-256 | `41b76c48fff44d62e34b463e52d1a4842f1b8c39711e6e1ac77ae6dbc3906f57` |
| `libssl3.so` Build ID | `25bf915d26112095d760d5826114e734620c399d` |
| Required hook pattern count | exactly 1 |
| Protocol minimum | TLS 1.3 |
| Protocol maximum | TLS 1.3 |
| Server address | `127.0.0.1:8443` |
| Browser control | WebDriver BiDi over loopback |
| Browser display | private Xvfb; Firefox headless |

The runner also verifies the frozen hashes of `firefox`, `firefox-bin`, `libnss3.so`, and `libsoftokn3.so`.

### 7.2 What the NSS hook observes

For Firefox 136.0.2, the target is the NSS TLS 1.3 derive-secret wrapper represented by one pinned byte pattern in `libssl3.so`.

The relevant function layout is treated as:

```text
tls13_DeriveSecretWrap(
    args[0] = sslSocket pointer,
    args[1] = source key,
    args[2] = client/server prefix,
    args[3] = label suffix,
    args[4] = human-readable key-log label,
    args[5] = destination PK11SymKey**
)
```

On function exit, the hook:

1. reads the destination key object;
2. calls `PK11_ExtractKeyValue`;
3. calls `PK11_GetKeyData`;
4. reads the resulting `SECItem`;
5. obtains the ClientHello random from the pinned NSS structures;
6. maps the NSS label to NSS key-log format;
7. emits a candidate line.

The explicit extraction call was essential. A PKCS#11/NSS key object does not necessarily expose usable bytes merely because its pointer exists.

### 7.3 Process selection

Firefox is multi-process. The network socket child maps NSS, but the observed TLS secret-derivation function for this pinned build executes in the Firefox parent process.

The runner records both:

```text
Firefox parent process
    |
    +--> Frida attaches here
    |
    +--> recorded as nss_tls_secret_derivation_process

Firefox network socket child
    |
    +--> maps libssl3.so
    +--> PID and memory map recorded for evidence
```

The process decision is recorded in:

```text
browser/process-map.json
frida/attached-processes.json
```

### 7.4 Hook-before-handshake timing

The most important synchronization mechanism is the TLS handshake gate.

```text
Runner          Firefox/BiDi          TLS server          Frida
  |                  |                    |                 |
  | start capture    |                    |                 |
  | start Firefox    |                    |                 |
  |----------------->|                    |                 |
  | queue navigation |                    |                 |
  |----------------->| TCP connect ------>|                 |
  |                  |              hold handshake          |
  | discover PID     |                    |                 |
  | attach/load hook |------------------------------------->|
  |                  |                    |        hook ready|
  |<--------------------------------------------------------|
  | enable measuring |                    |                 |
  | release gate     |------------------->|                 |
  |                  | TLS handshake <--------------------->|
  |                  | HTTP request ----->|                 |
  |                  |<----- marker page  |                 |
  | stop measuring   |                    |                 |
  | validate PCAP    |                    |                 |
```

Navigation is queued before Frida attachment while Firefox is responsive. The server accepts the TCP connection but does not begin TLS until Frida reports the hook is ready. This prevents a measured secret from being derived before instrumentation is active.

### 7.5 Controlled workload

Each case receives a unique request:

```text
/lab?case=<CASE_ID>&run=<RUN_ID>&request_id=REQUEST-0001&nonce=<NONCE>
```

The server response contains:

```text
TLSKH|<CASE_ID>|<RUN_ID>|TLS1.3|REQUEST-0001|NONCE-<NONCE>
```

The nonce is derived from the case ID, run ID, and start time. It prevents a stale page or unrelated decrypted stream from satisfying the acceptance test.

The server is pinned to TLS 1.3, HTTP/1.1, and `Connection: close`. Firefox preferences disable HTTP/3 and background services that could introduce unrelated traffic.

---

## 8. Development mode and measurement mode

### 8.1 Development mode

Development mode sets an internal Firefox `SSLKEYLOGFILE` and produces:

```text
secrets/dev-ground-truth.keys
```

A candidate enters functional validation only if:

1. its ClientHello random appears in the captured PCAP; and
2. it exactly equals a development ground-truth line.

Development mode was used to discover and debug:

- the correct process;
- the NSS function signature;
- label handling;
- secret extraction;
- candidate formatting;
- request/response verification.

### 8.2 Measurement mode

Measurement mode does **not** set `SSLKEYLOGFILE` and does not create development ground truth.

```text
Frida candidates
       |
       v
Keep candidates whose ClientHello random occurs in the PCAP
       |
       v
Temporary candidate key-log file
       |
       v
TShark authenticated TLS decryption
       |
       +--> exact unique request path?
       +--> exact unique response marker and nonce?
       |
       v
Accept candidates and session only if both are recovered
```

The temporary key-log file is staged under `/tmp`, used for verification, and moved into the case as `secrets/verified.keys` only when the case is accepted.

### 8.3 Required TLS 1.3 labels

A complete handshake requires at least:

- `CLIENT_HANDSHAKE_TRAFFIC_SECRET`;
- `SERVER_HANDSHAKE_TRAFFIC_SECRET`;
- `CLIENT_TRAFFIC_SECRET_0`;
- `SERVER_TRAFFIC_SECRET_0`.

The accepted cases also observed `EXPORTER_SECRET`.

### 8.4 Session count versus candidate-event count

One experimental session is one controlled request/response evidence unit. It is not one Frida event.

NSS may emit multiple label-specific secrets and may derive secrets for more than one observed connection. Therefore:

```text
1 session
    !=
1 Frida event
```

The final dataset produced 10 verified candidate groups per accepted session, or 900 groups over 90 sessions. The primary metric remains session recovery coverage.

---

## 9. Acceptance and exclusion rules

### 9.1 Accepted session

A session is `Eligible and fully recovered` only when all of these are true:

- controlled browser workload event exists;
- matching controlled server event exists;
- a complete TLS handshake exists in the PCAP;
- at least one relevant Frida candidate event exists;
- candidate ClientHello random is present in the PCAP;
- TShark authenticates and decrypts the TLS application records;
- exact controlled request path is recovered;
- exact controlled response marker and nonce are recovered;
- verification and evidence files are included in the manifest.

### 9.2 Exclusion or unverified conditions

A case is rejected or remains unverified if any of these occur:

- fingerprint hash or Build ID mismatch;
- pattern count is not exactly one;
- browser failure;
- Frida failure;
- missing controlled server event;
- incomplete handshake;
- no candidate;
- candidate validation failure;
- missing exact request;
- missing exact response marker.

The campaign runner returns exit code 0 only when every attempted campaign session is fully recovered. A partially successful campaign returns exit code 2.

---

## 10. Evidence structure

A finalized Firefox case resembles:

```text
cases/<CASE_ID>/
|
+-- case.yaml
+-- environment/
|   +-- environment.json
|   +-- installed-packages.txt
|   +-- process-list-before.txt
|   +-- process-list-after.txt
|   +-- network-before.txt
|   +-- network-after.txt
|
+-- target-artifacts/
|   +-- hashes.json
|   +-- build-ids.json
|   +-- fingerprint-validation.json
|   +-- firefox-nss-profile.json
|
+-- browser/
|   +-- workload-events.jsonl
|   +-- navigation-command.json
|   +-- process-map.json
|   +-- profile-settings.json
|   +-- firefox-stdout.log
|   +-- firefox-stderr.log
|
+-- capture/
|   +-- traffic.pcapng
|   +-- capture-command.txt
|   +-- capture-diagnostics.log
|
+-- server/
|   +-- server-events.jsonl
|   +-- server-access.log
|   +-- certificate-info.txt
|
+-- frida/
|   +-- frida-events.jsonl
|   +-- frida-diagnostics.log
|   +-- hook-summary.json
|   +-- attached-processes.json
|
+-- secrets/
|   +-- candidates.keys
|   +-- verified.keys
|   +-- candidate-hashes.json
|
+-- verification/
|   +-- verification.json
|   +-- tshark-output.log
|   +-- decrypted-streams.tsv
|   +-- decrypted-body-evidence.json
|   +-- candidate-associations.json
|   +-- streams.json
|
+-- metrics/
|   +-- metrics.json
|   +-- run-summary.csv
|   +-- confidence-interval.json
|
+-- visual/
+-- reports/
+-- evidence-manifest.sha256
```

### Secret-bearing files

The following files must remain private:

- `secrets/candidates.keys`;
- `secrets/verified.keys`;
- `secrets/dev-ground-truth.keys`, when present;
- server private keys;
- PCAPs when research policy treats them as sensitive.

They are created with mode `600`; directories use mode `700`.

Public reports should use candidate IDs, hashes, counts, and Boolean verification results—not raw secret bytes.

---

## 11. What did not work and how it was solved

### 11.1 SSH initially timed out

**Symptom**

```text
ssh: connect to host 89.167.33.8 port 22: Operation timed out
nc ... port 22 ... Operation timed out
```

**Cause**

The client’s public source IP had changed and did not match the VPS firewall allowlist.

**Solution**

The current client IP was checked with:

```bash
curl -4 ifconfig.me
```

The trusted firewall source was updated, after which SSH succeeded. A timeout at this stage was a network/firewall problem, not an SSH username or host-key problem.

### 11.2 Direct packet capture into the case directory failed

**Symptom**

```text
dumpcap: ... traffic.pcapng could not be opened: Permission denied
```

**Cause**

The capture process and researcher-owned evidence directory did not have compatible ownership/permissions.

**Solution**

Capture now writes to a unique staging path under `/tmp`. After dumpcap closes cleanly, the runner:

1. sets restrictive permissions;
2. assigns researcher ownership;
3. moves the completed PCAP into the case directory.

### 11.3 Firefox started but produced zero captured packets

**Symptom**

Several early pilots installed the pattern hook but captured zero packets.

**Cause**

Firefox navigation and Frida attachment had a timing/deadlock problem. Starting navigation too late left the controlled workload untriggered; attaching too early could make browser control unresponsive.

**Solution**

WebDriver BiDi queues navigation first, while the server’s handshake gate prevents TLS key derivation. Frida attaches and reports hook readiness, then the gate opens.

### 11.4 GUI-oriented browser control was unreliable

**Symptom**

Remote visible Firefox automation and agent-driven GUI interaction hung or failed to progress reliably.

**Solution**

The authoritative run was changed to deterministic headless Firefox controlled through WebDriver BiDi over loopback. A private Xvfb display and `twm` are still created for a controlled display environment.

**Limitation**

This differs from the plan’s preferred live VNC/GUI final evidence. The generated PNGs are post-run status images, not proof of live interactive scrolling. No final screen recording was captured. The authoritative evidence is the PCAP, Frida events, server logs, TShark output, and manifests.

### 11.5 Firefox sandbox/seccomp failures

**Symptom**

Early pilots showed socket-process seccomp violations and channel errors.

**Cause**

Frida process handling conflicted with Firefox’s isolated socket-process sandbox in the disposable lab environment.

**Solution**

The runner uses:

```text
MOZ_DISABLE_SOCKET_PROCESS_SANDBOX=1
security.sandbox.socket.process.level=0
```

This applies only to the disposable, controlled Firefox profile/process tree. The setting and reason are recorded in `browser/instrumentation-environment.json`.

### 11.6 The apparent network process was not the derivation process

**Symptom**

Attaching based only on the process that mapped the network socket did not reliably yield the desired secret events.

**Cause**

For the pinned Firefox build, the observed TLS secret-derivation function executed in the parent process.

**Solution**

The runner records both processes but attaches Frida to the parent, identified as `nss_tls_secret_derivation_process`.

### 11.7 NSS key objects did not immediately expose bytes

**Symptom**

The correct derive-secret hook ran, but key data was unavailable or empty.

**Cause**

The NSS `PK11SymKey` value had not been explicitly exposed for retrieval.

**Solution**

The hook calls `PK11_ExtractKeyValue` before `PK11_GetKeyData`, then reads the returned `SECItem`.

### 11.8 Request recovery worked but response marker recovery failed

**Symptom**

Pilot 023 recovered the request path but not the exact response marker.

**Cause**

TShark’s `http.file_data` field can contain hex-encoded body bytes. Searching only the textual TShark output missed the marker.

**Solution**

The runner now removes field separators, decodes valid hex bodies, and searches the reconstructed bytes for the exact marker. Pilot 024 and later cases recovered both sides.

### 11.9 Development ground truth could contaminate measurement claims

**Problem**

If Firefox writes `SSLKEYLOGFILE` during a final run, successful decryption cannot independently demonstrate Frida extraction.

**Solution**

The runner has explicit `development` and `measurement` modes. Measurement mode does not configure `SSLKEYLOGFILE`. It verifies candidates through PCAP association and authenticated request/response decryption.

### 11.10 Version-specific patterns could attach to the wrong binary

**Problem**

A byte pattern may be invalid for a changed Firefox/NSS build or may occur more than once.

**Solution**

Before Firefox starts, the runner checks:

- exact SHA-256 hashes;
- ELF Build IDs;
- exactly one pattern match.

Unsupported hashes and multiple-match policies were tested as rejection controls.

### 11.11 Random-byte scanning produced incorrect wolfSSL lengths

**Problem**

The old TLS 1.3 wolfSSL hook treated zero bytes as terminators. Random cryptographic material may contain zeros.

**Solution**

The hook maps wolfSSL’s hash identifier to a defined digest length and rejects unknown values.

### 11.12 Ranker rejection was undermined by hardcoded fallback

**Problem**

Returning to the previous hardcoded argument after the ranker found no candidate would convert uncertainty into false output.

**Solution**

The OpenSSL selection helper records `fallback_disabled` and returns `null`. Extraction is skipped.

### 11.13 Experimental consistency across cases

**Problem**

Generating a new certificate or changing source between sessions introduces avoidable variation.

**Solution**

- a fixed certificate bundle was created at `/opt/tlskeyhunter/frozen-cert-v1`;
- the campaign refuses to run from a dirty Git worktree;
- every case records source and binary hashes;
- the final campaign records the commit;
- manifests protect every finalized evidence file.

---

## 12. Results generated

### 12.1 Ranker tests

Eight tests passed:

1. accepts readable high-entropy expected-length secrets;
2. rejects zero-filled low-entropy data;
3. rejects invalid or unreadable pointers;
4. accepts known TLS labels and rejects unrelated strings;
5. applies repeated-call consistency only when enabled;
6. supports length-only ablation;
7. requires expected integer values;
8. requires structural preference at the default threshold.

### 12.2 wolfSSL results

Both controlled baselines were accepted:

```text
TLS 1.2: 1/1 fully recovered
TLS 1.3: 1/1 fully recovered
```

### 12.3 Firefox development result

The accepted development case `FIREFOX-NSS-TLS13-PILOT-025` produced:

- one fully recovered session;
- 10 Frida candidate events;
- 10 verified candidate groups;
- five TLS 1.3 label types;
- exact request and response recovery.

### 12.4 Firefox ground-truth-free pilot

The five-session campaign `FIREFOX-NSS-TLS13-PILOT-CAMPAIGN-001` produced:

```text
5/5 fully recovered
50 verified candidate groups
100% session recovery coverage
95% Wilson lower bound: 56.55%
```

The wide interval is expected for only five observations.

### 12.5 Final Firefox measurement campaign

Campaign:

```text
FIREFOX-NSS-TLS13-FINAL-MEASURED-001
```

Results:

```text
Run 1: 30/30
Run 2: 30/30
Run 3: 30/30
Total: 90/90
Coverage: 100%
Frida events: 900
Verified candidate groups: 900
Failed sessions: 0
95% Wilson interval: 95.91% to 100%
```

The JSON’s floating-point upper value is `1.0000000000000002`. It should be displayed as 100%, because the tiny excess is numerical floating-point error rather than a probability greater than one.

### 12.6 Negative controls

| Control | Expected result | Observed |
|---|---|---|
| No key-log file | No request or marker recovery | Passed |
| Random secret, correct length | No request or marker recovery | Passed |
| One-bit modified secret | No request or marker recovery | Passed |
| Correct secret, wrong ClientHello random | No request or marker recovery | Passed |
| Frida diagnostics as key log | No request or marker recovery | Passed |
| Correct candidate, wrong TCP stream | No request or marker recovery | Passed |
| Unsupported NSS hash/Build ID | Extraction blocked | Passed |
| Multiple pattern matches | Extraction blocked | Passed |

The positive sanity control recovered the exact request and exact response marker.

---

## 13. Laboratory environment

Frozen versions:

| Tool | Version |
|---|---|
| Ubuntu kernel | Linux `7.0.0-28-generic` |
| Firefox | 136.0.2 |
| Frida | 16.7.19 |
| Frida tools | 13.7.1 |
| Python | 3.14.4 |
| WebSockets | 13.1 |
| TShark | 4.6.4 |
| Node.js | v22.22.1 |
| Java | OpenJDK 21.0.11 |
| OpenSSL | 3.5.5 |

Ghidra was not detected under `/opt` by the freeze script. The repository contains Ghidra support and a downloaded archive under `.tools`, but the final dynamic measurement did not depend on rerunning Ghidra.

Required operational commands include:

```text
certutil
dumpcap
tshark
Xvfb
twm
node
jq
sha256sum
```

---

## 14. Connecting to the lab

From the Mac:

```bash
curl -4 ifconfig.me
nc -vz -w 5 89.167.33.8 22
ssh researcher@89.167.33.8
```

Use root only for the wolfSSL baseline runner, which explicitly requires it:

```bash
ssh root@89.167.33.8
```

After connecting:

```bash
cd /home/researcher/research/TLSKeyHunter
source /home/researcher/.venv/bin/activate
```

When connected as `researcher`, check the frozen branch:

```bash
git status --short --branch
git rev-parse HEAD
```

Expected branch and commit:

```text
codex/plan-v2-completion
e0104374f113fd00a8f03bcadce46573b71e5951
```

---

## 15. Running tests

### 15.1 Syntax and Python compilation

```bash
cd /home/researcher/research/TLSKeyHunter

node --check tlsKeyExtraction/arg_ranker.js
node --check lab/firefox/nss_firefox_136.0.2.js

/home/researcher/.venv/bin/python -m py_compile \
  lab/baseline/run_wolfssl_baseline.py \
  lab/firefox/phase18a_firefox_nss_runner.py \
  lab/firefox/run_campaign.py \
  lab/firefox/run_negative_controls.py \
  lab/firefox/create_fixed_certificate.py \
  lab/freeze_experiment.py
```

### 15.2 Ranker tests and ablation

```bash
node tests/test_arg_ranker.js

node tests/run_arg_ranker_ablation.js \
  research_notes/arg_ranker_ablation-rerun.json

jq '.summary' research_notes/arg_ranker_ablation-rerun.json
```

Use a new output filename to preserve the frozen result.

---

## 16. Running a new wolfSSL baseline

Run these commands as root. Case IDs must be unique because the runner refuses to overwrite existing evidence.

### TLS 1.2

```bash
cd /home/researcher/research/TLSKeyHunter

/home/researcher/.venv/bin/python \
  lab/baseline/run_wolfssl_baseline.py \
  --repo /home/researcher/research/TLSKeyHunter \
  --protocol 12 \
  --case-id BASELINE-WOLFSSL-TLS12-RERUN-001
```

### TLS 1.3

```bash
cd /home/researcher/research/TLSKeyHunter

/home/researcher/.venv/bin/python \
  lab/baseline/run_wolfssl_baseline.py \
  --repo /home/researcher/research/TLSKeyHunter \
  --protocol 13 \
  --case-id BASELINE-WOLFSSL-TLS13-RERUN-001
```

View the result:

```bash
jq . cases/BASELINE-WOLFSSL-TLS13-RERUN-001/verification/verification.json
jq . cases/BASELINE-WOLFSSL-TLS13-RERUN-001/metrics/metrics.json

cd cases/BASELINE-WOLFSSL-TLS13-RERUN-001
sha256sum -c evidence-manifest.sha256
```

---

## 17. Running one Firefox/NSS session

### 17.1 Pre-run checks

Run the Firefox runner from the `researcher` account. The installed dumpcap
capabilities allow loopback capture, and the runner's researcher-scoped
subprocess calls are permitted. Running the campaign as root is discouraged
because the repository is researcher-owned and Git may reject it as having
"dubious ownership."

```bash
cd /home/researcher/research/TLSKeyHunter
unset SSLKEYLOGFILE

test -x /opt/tlskeyhunter/firefox-136.0.2-pristine/firefox
test -f /opt/tlskeyhunter/frozen-cert-v1/ca.cert.pem
test -f /opt/tlskeyhunter/frozen-cert-v1/server.cert.pem
test -f /opt/tlskeyhunter/frozen-cert-v1/server.key.pem

git status --short
```

### 17.2 Development session

Development mode creates independent Firefox ground truth internally:

```bash
/home/researcher/.venv/bin/python \
  lab/firefox/phase18a_firefox_nss_runner.py \
  --case-dir cases/FIREFOX-NSS-TLS13-DEV-RERUN-001 \
  --case-id FIREFOX-NSS-TLS13-DEV-RERUN-001 \
  --run-id RUN-01 \
  --mode development \
  --port 8443 \
  --firefox /opt/tlskeyhunter/firefox-136.0.2-pristine/firefox \
  --hook lab/firefox/nss_firefox_136.0.2.js \
  --fingerprints lab/firefox/firefox_nss_fingerprints.json \
  --certificate-dir /opt/tlskeyhunter/frozen-cert-v1
```

Use development mode when changing hooks, process selection, or validation logic. Do not mix development cases into the final measurement dataset.

### 17.3 Measurement session

```bash
/home/researcher/.venv/bin/python \
  lab/firefox/phase18a_firefox_nss_runner.py \
  --case-dir cases/FIREFOX-NSS-TLS13-MEASURED-RERUN-001 \
  --case-id FIREFOX-NSS-TLS13-MEASURED-RERUN-001 \
  --run-id RUN-01 \
  --mode measurement \
  --port 8443 \
  --firefox /opt/tlskeyhunter/firefox-136.0.2-pristine/firefox \
  --hook lab/firefox/nss_firefox_136.0.2.js \
  --fingerprints lab/firefox/firefox_nss_fingerprints.json \
  --certificate-dir /opt/tlskeyhunter/frozen-cert-v1
```

Expected successful final line contains:

```text
"status": "Eligible and fully recovered"
```

The runner returns:

- `0` for an accepted session;
- `2` for an unverified completed session;
- another nonzero status for a runner failure.

---

## 18. Running a Firefox campaign

### 18.1 Small pilot

The campaign runner requires a clean Git worktree.

```bash
cd /home/researcher/research/TLSKeyHunter
unset SSLKEYLOGFILE

git status --short

/home/researcher/.venv/bin/python \
  lab/firefox/run_campaign.py \
  --repo /home/researcher/research/TLSKeyHunter \
  --campaign-id FIREFOX-NSS-TLS13-PILOT-RERUN-001 \
  --runs 1 \
  --sessions-per-run 5 \
  --mode measurement \
  --certificate-dir /opt/tlskeyhunter/frozen-cert-v1 \
  --firefox /opt/tlskeyhunter/firefox-136.0.2-pristine/firefox
```

### 18.2 Full 3 × 30 campaign

Only run a new final campaign when the protocol, code, certificate, fingerprints, and scoring policy are frozen.

```bash
cd /home/researcher/research/TLSKeyHunter
unset SSLKEYLOGFILE

/home/researcher/.venv/bin/python \
  lab/firefox/run_campaign.py \
  --repo /home/researcher/research/TLSKeyHunter \
  --campaign-id FIREFOX-NSS-TLS13-FINAL-MEASURED-002 \
  --runs 3 \
  --sessions-per-run 30 \
  --mode measurement \
  --certificate-dir /opt/tlskeyhunter/frozen-cert-v1 \
  --firefox /opt/tlskeyhunter/firefox-136.0.2-pristine/firefox
```

The runner creates:

```text
results/<CAMPAIGN_ID>/campaign-summary.json
results/<CAMPAIGN_ID>/sessions.csv
results/<CAMPAIGN_ID>/evidence-manifest.sha256
```

Each session receives its own case:

```text
cases/<CAMPAIGN_ID>-R01-S001
...
cases/<CAMPAIGN_ID>-R03-S030
```

Do not reuse an existing campaign ID.

---

## 19. Running negative controls

Choose one accepted measurement case:

```bash
cd /home/researcher/research/TLSKeyHunter

/home/researcher/.venv/bin/python \
  lab/firefox/run_negative_controls.py \
  --case-dir cases/FIREFOX-NSS-TLS13-MEASURED-RERUN-001 \
  --output-dir cases/NEGATIVE-CONTROLS-TLS13-RERUN-001 \
  --libssl3 /opt/tlskeyhunter/firefox-136.0.2-pristine/libssl3.so
```

Inspect:

```bash
jq . cases/NEGATIVE-CONTROLS-TLS13-RERUN-001/negative-controls.json

cd cases/NEGATIVE-CONTROLS-TLS13-RERUN-001
sha256sum -c evidence-manifest.sha256
```

Required success fields:

```text
positive_sanity.passed = true
all_negative_controls_passed = true
secrets_in_report = false
```

---

## 20. Freezing a changed experiment

Do not create a new freeze merely to rerun unchanged sessions. Create a new freeze when a measured input changes.

If the hook, runner, certificate, Firefox build, fingerprint policy, or scoring changes:

1. commit the change;
2. ensure the worktree is clean;
3. rerun development validation;
4. rerun the pilot and controls;
5. create a new freeze directory;
6. start a new measured campaign.

Example:

```bash
cd /home/researcher/research/TLSKeyHunter

/home/researcher/.venv/bin/python \
  lab/freeze_experiment.py \
  --repo /home/researcher/research/TLSKeyHunter \
  --output-dir cases/FROZEN-BASELINE-V4 \
  --certificate-dir /opt/tlskeyhunter/frozen-cert-v1 \
  --firefox /opt/tlskeyhunter/firefox-136.0.2-pristine/firefox \
  --reference-case BASELINE-WOLFSSL-TLS12-014 \
  --reference-case BASELINE-WOLFSSL-TLS13-001 \
  --reference-case FIREFOX-NSS-TLS13-PILOT-RERUN-001-R01-S001 \
  --reference-case NEGATIVE-CONTROLS-TLS13-RERUN-001
```

The freeze script refuses a dirty repository and refuses to overwrite a non-empty freeze directory.

---

## 21. Viewing and verifying results

### 21.1 Final campaign summary

On the VPS:

```bash
cd /home/researcher/research/TLSKeyHunter

jq 'del(.sessions)' \
  results/FIREFOX-NSS-TLS13-FINAL-MEASURED-001/campaign-summary.json
```

Show each session:

```bash
column -s, -t \
  < results/FIREFOX-NSS-TLS13-FINAL-MEASURED-001/sessions.csv \
  | less -S
```

Show failed sessions only:

```bash
jq '.sessions[] | select(.fully_recovered != true)' \
  results/FIREFOX-NSS-TLS13-FINAL-MEASURED-001/campaign-summary.json
```

An empty result means no failed sessions were recorded.

### 21.2 One case

```bash
CASE_DIR=cases/FIREFOX-NSS-TLS13-FINAL-MEASURED-001-R03-S030

jq . "$CASE_DIR/verification/verification.json"
jq . "$CASE_DIR/metrics/metrics.json"
jq . "$CASE_DIR/frida/hook-summary.json"
jq . "$CASE_DIR/target-artifacts/fingerprint-validation.json"
jq . "$CASE_DIR/secrets/candidate-hashes.json"
less "$CASE_DIR/reports/run-report.md"
```

`candidate-hashes.json` is suitable for inspection because it contains IDs and hashes rather than raw key material.

### 21.3 Verify campaign files

```bash
cd /home/researcher/research/TLSKeyHunter/results/FIREFOX-NSS-TLS13-FINAL-MEASURED-001
sha256sum -c evidence-manifest.sha256
```

### 21.4 Verify all 90 case manifests

```bash
cd /home/researcher/research/TLSKeyHunter

failed=0
checked=0

for manifest in \
  cases/FIREFOX-NSS-TLS13-FINAL-MEASURED-001-R*/evidence-manifest.sha256
do
  case_dir=${manifest%/*}
  if ! (cd "$case_dir" && sha256sum -c --quiet evidence-manifest.sha256)
  then
    echo "FAILED: $case_dir"
    failed=$((failed + 1))
  fi
  checked=$((checked + 1))
done

echo "checked=$checked failures=$failed"
```

Expected:

```text
checked=90 failures=0
```

### 21.5 Inspect decrypted application evidence

```bash
CASE_DIR=cases/FIREFOX-NSS-TLS13-FINAL-MEASURED-001-R03-S030

cat "$CASE_DIR/verification/decrypted-streams.tsv"
jq . "$CASE_DIR/verification/decrypted-body-evidence.json"
jq . "$CASE_DIR/verification/streams.json"
```

The stream record exposes the request path and a hash of the marker, not the raw secret.

### 21.6 Open the PCAP in Wireshark

Only do this inside the controlled lab because `verified.keys` contains sensitive key material.

Copy both files to an approved protected directory on the Mac:

```bash
mkdir -p "/Users/shanilka/Documents/TLS Key Thesis/pcap-review"

scp \
  researcher@89.167.33.8:/home/researcher/research/TLSKeyHunter/cases/FIREFOX-NSS-TLS13-FINAL-MEASURED-001-R03-S030/capture/traffic.pcapng \
  "/Users/shanilka/Documents/TLS Key Thesis/pcap-review/"

scp \
  researcher@89.167.33.8:/home/researcher/research/TLSKeyHunter/cases/FIREFOX-NSS-TLS13-FINAL-MEASURED-001-R03-S030/secrets/verified.keys \
  "/Users/shanilka/Documents/TLS Key Thesis/pcap-review/"
```

In Wireshark:

```text
Preferences
  -> Protocols
  -> TLS
  -> (Pre)-Master-Secret log filename
  -> select verified.keys
```

Useful display filters:

```text
tls.handshake
http
http.request
tcp.stream eq 0
```

Delete or securely archive the copied key file after review.

### 21.7 Local non-secret summaries

Non-secret copies are stored under:

```text
TLSKeyHunter-work/evidence-summaries/
```

Important files:

```text
FIREFOX-NSS-TLS13-FINAL-MEASURED-001/campaign-summary.json
FIREFOX-NSS-TLS13-FINAL-MEASURED-001/sessions.csv
NEGATIVE-CONTROLS-FIREFOX-NSS-TLS13-FINAL-001/negative-controls.json
FROZEN-BASELINE-V3/evidence-manifest.sha256
```

On macOS, verify these with:

```bash
cd "/Users/shanilka/Documents/TLS Key Thesis/TLSKeyHunter-work/evidence-summaries"

(cd FIREFOX-NSS-TLS13-FINAL-MEASURED-001 \
  && shasum -a 256 -c evidence-manifest.sha256)

(cd NEGATIVE-CONTROLS-FIREFOX-NSS-TLS13-FINAL-001 \
  && shasum -a 256 -c evidence-manifest.sha256)

(cd FROZEN-BASELINE-V3 \
  && shasum -a 256 -c evidence-manifest.sha256)
```

---

## 22. Troubleshooting guide

```text
SSH times out
  |
  +--> check curl -4 ifconfig.me
  +--> check firewall /32 source
  +--> test nc -vz -w 5 89.167.33.8 22

Runner refuses case
  |
  +--> case already finalized?
  +--> choose a new case/campaign ID

Campaign refuses to start
  |
  +--> run git status --short as researcher
  +--> commit or intentionally handle changes before measurement

Fingerprint rejected
  |
  +--> inspect target-artifacts/fingerprint-validation.json
  +--> do not bypass the policy
  +--> treat new binary as a new target requiring static analysis

No packets
  |
  +--> inspect capture/capture-diagnostics.log
  +--> inspect browser/navigation-command.json
  +--> confirm port 8443 is free

Hook not ready
  |
  +--> inspect frida/frida-diagnostics.log
  +--> inspect frida/hook-summary.json
  +--> confirm the exact pinned Firefox hashes

Handshake exists but no candidates
  |
  +--> confirm Frida attached to the recorded parent PID
  +--> inspect attached-processes.json and memory maps
  +--> confirm PK11_ExtractKeyValue succeeded

Request recovered but marker missing
  |
  +--> inspect decrypted-streams.tsv
  +--> inspect decrypted-body-evidence.json
  +--> confirm http.file_data was decoded as bytes

Manifest failure
  |
  +--> preserve the case
  +--> do not edit evidence in place
  +--> investigate which file changed
  +--> rerun using a new case ID if evidence is invalid
```

Check for lingering lab processes:

```bash
pgrep -af 'firefox|geckodriver|phase18a_firefox_nss_runner|dumpcap|Xvfb'
```

An empty result is expected after a cleanly completed case.

---

## 23. Safety, integrity, and reproducibility rules

1. Run only against the authorized controlled lab targets.
2. Never expose the Firefox endpoint or certificate private key outside the lab.
3. Do not commit raw key-log files or sensitive PCAPs.
4. Do not weaken fingerprint checks to make a new Firefox build run.
5. Do not count a candidate merely because it has the right length or entropy.
6. Do not count a session without both request and response recovery.
7. Do not modify a finalized evidence directory.
8. Use a new case ID for every attempt.
9. If measured code or inputs change, freeze again and restart the affected dataset.
10. Preserve failed pilots separately; do not mix them with final measured results.

---

## 24. Completion matrix against the plan

| Plan item | Status | Evidence or limitation |
|---|---|---|
| VPS access and trusted firewall source | Complete | SSH verified |
| Normal `researcher` account | Complete | Repository and evidence owned by researcher |
| Base tools and Python/Frida environment | Complete | Frozen tool versions |
| Original repository inspection | Complete | Hooks and argument locations reviewed |
| Controlled TLS server and capture | Complete | wolfSSL and Firefox runners |
| wolfSSL TLS 1.2 baseline | Complete | `BASELINE-WOLFSSL-TLS12-014` |
| wolfSSL TLS 1.3 baseline | Complete | `BASELINE-WOLFSSL-TLS13-001` |
| `arg_ranker` implementation | Complete | module, thresholds, tests |
| Ranker “no candidate” behavior | Complete | tested and OpenSSL fallback disabled |
| Ranker unit tests | Complete | 8/8 pass |
| Four-way ranker ablation | Fixture complete | deterministic fixture, not live libraries |
| Analyst effort reduction | Not measured | no timing dataset |
| Firefox 136.0.2/NSS TLS 1.3 hook | Complete | fingerprint-gated hook |
| Firefox development ground truth | Complete | accepted pilot |
| Firefox measurement without ground truth | Complete | accepted pilots and final campaign |
| Five-session TLS 1.3 pilot | Complete | 5/5 |
| Frozen experiment inputs | Complete | `FROZEN-BASELINE-V3` |
| TLS 1.3 final 3 × 30 | Complete | 90/90 |
| TLS 1.3 negative controls | Complete | 8/8 |
| All final per-case manifests | Complete | 90/90 valid |
| TLS 1.2 Firefox endpoint/hook | Not complete | separate implementation required |
| TLS 1.2 Firefox pilot | Not complete | no dataset |
| TLS 1.2 Firefox final 3 × 30 | Not complete | no dataset |
| Live final GUI/VNC evidence | Not complete | headless authoritative run |
| Final screen recording | Not complete | explicitly recorded as not captured |
| Ghidra frozen installation/version | Not complete | freeze recorded `detected: false` |

---

## 25. Correct interpretation for a thesis

The evidence supports the following claims:

- the controlled baseline workflow successfully extracted and independently verified wolfSSL TLS 1.2 and TLS 1.3 secrets;
- the ranker’s confidence logic, rejection behavior, and ablation controls work in deterministic tests;
- the pinned Firefox 136.0.2/NSS TLS 1.3 hook produced candidates that independently decrypted all 90 final controlled sessions;
- the final Firefox TLS 1.3 session recovery estimate was 100%, with a 95% Wilson interval of approximately 95.91% to 100%;
- eight designed negative controls did not recover the protected request or response, while the positive sanity input did;
- source, target binaries, certificate artifacts, policies, and results were hashed and frozen.

The evidence does **not** support these broader claims:

- that arbitrary Firefox versions are supported;
- that the NSS hook is version-independent;
- that Firefox TLS 1.2 has been completed;
- that `arg_ranker` achieved 100% on live TLS libraries;
- that analyst effort was quantitatively reduced;
- that the final campaign used a visible interactive GUI;
- that every original TLSKeyHunter library was revalidated.

---

## 26. Final research rule

```text
Candidate appearance is not evidence.

Length is not evidence.
Entropy is not evidence.
A matching label is not evidence.
Encrypted TLS application data is not evidence.

Exact independent equality during development,
or authenticated recovery of the exact controlled
request and response during measurement,
is evidence.
```
