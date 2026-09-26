# TLSKeyHunter Live-Memory Forensics Thesis Report v3

**Project:** Improving the Robustness of Static-to-Dynamic TLS Key Extraction  
**Upstream basis:** `monkeywave/TLSKeyHunter`  
**Experiment branch:** `codex/v2-gap-closure`  
**Frozen experiment commit:** `e65078b5f0be41e61ec9fbdd323133352a9b58eb`  
**Frozen environment:** `FROZEN-BASELINE-V4`  
**Scope:** Authorized, controlled localhost/VPS TLS research only  
**Report generated:** 2026-08-30

## 1. Executive outcome

This thesis returns to the original live-memory-forensics question: can a TLS secret candidate be acquired from an active process, fixed before verification, proven byte-for-byte against an independent reference, and then used to decrypt the intended captured connection?

For the principal Firefox/NSS TLS 1.2 experiment, the answer was **30/30 complete recoveries**. Every session used a fresh Firefox 136.0.2 profile, a single controlled TLS 1.2 connection, a frozen NSS fingerprint, a live Frida hook, an isolated server-side reference, and a PCAP. Every candidate was sealed before the server reference was read or TShark verification began.

| Principal Firefox TLS 1.2 metric | Result |
|---|---:|
| Attempted sessions | 30 |
| Sealed acquisitions | 30 |
| Exact server-reference matches | 30 |
| Authenticated decryptions | 30 |
| Complete end-to-end recoveries | 30 |
| Coverage | 100.0% |
| 95% Wilson interval | 88.65%–100.00% |
| Valid session manifests | 30/30 |

This is a proof of concept under frozen laboratory conditions, not a claim that arbitrary Firefox versions or remote systems can be instrumented without version-specific validation.

## 2. Research contribution and scope

The upstream project provides the static-analysis foundation: TLS-related strings and functions are identified in Ghidra and converted into usable fingerprints. This work preserves that upstream basis and adds a controlled evidence pipeline:

```text
active TLS process
→ unique frozen static fingerprint
→ Frida live-memory acquisition
→ candidate selection
→ immutable acquisition seal
→ independent exact comparison
→ authenticated PCAP decryption
→ manifested evidence and non-secret metrics
```

Firefox/NSS is the principal real-world browser target. OpenSSL and wolfSSL are controlled comparison targets for argument-selection robustness. The original accepted Firefox TLS 1.3 campaign remains immutable supporting evidence. Later B/C ablations, an operator-effort microbenchmark, and synthetic GUI generation were removed from the required scope so the thesis claim remains narrow and defensible.

The work does not alter or erase the original creators' implementation. New runners and hooks are version-specific extensions, and historical exploratory evidence is retained but excluded from final claims where its chronology differs from the final method.

## 3. Forensic chronology and information isolation

The final experiment enforces this order:

1. Start packet capture and the controlled server.
2. Launch the target with a fresh profile and with target `SSLKEYLOGFILE` disabled.
3. Validate the frozen binary SHA-256, ELF Build ID, and exactly one fingerprint match.
4. Attach Frida and confirm the live hook before releasing the handshake gate.
5. Acquire and select a candidate using only target-process observations.
6. Stop acquisition, write the selected candidate to owner-readable evidence, hash it, and record `acquisition_sealed=true`.
7. Only then read the separate server reference and perform byte-for-byte comparison.
8. Use only the sealed candidate for TShark decryption and require the exact request path and response marker.

The verifier never tries candidates until one decrypts. A missing candidate is `no_candidate`; an equal top rank is `ambiguous`; a plausible but unequal candidate is a false candidate. All remain in their denominators.

## 4. Static-to-dynamic provenance

V4 records Ghidra 12.0.4 at `/home/researcher/research/TLSKeyHunter/.tools/ghidra_12.0.4_PUBLIC/support/analyzeHeadless`, with headless status `ready` and application-properties SHA-256 `5b171b044c3883a4b4a7a6287d35c4dbf12858aaff1d95a9aac8402215bcaa94`.

| Target | SHA-256 | Build ID | Static offset | Pattern matches | Hook |
|---|---|---|---:|---:|---|
| Firefox TLS 1.2 `libsoftokn3.so` | `064c24743abe22bc8c9b87c6f8c4d7e8facc66d94a73b7ed9702e1d2733d2fe7` | `31e5530c1738a4fc6066623dea8554f39b0c11f4` | `0x0001ca00` | 1 | `nss_firefox_136.0.2_tls12.js` |
| Firefox TLS 1.3 `libssl3.so` | `41b76c48fff44d62e34b463e52d1a4842f1b8c39711e6e1ac77ae6dbc3906f57` | `25bf915d26112095d760d5826114e734620c399d` | `0x00056e90` | 1 | `nss_firefox_136.0.2.js` |

Zero or multiple fingerprint matches stop extraction. TLS 1.2 targets the NSS `TLS_PRF`-equivalent path referenced by `master secret`; its successful 48-byte result is associated with the controlled PCAP ClientHello random.

## 5. Candidate selection: A versus D

Only two methods are in the final comparison:

- **A:** the original per-hook hardcoded argument position.
- **D:** readability + expected length + entropy/zero-count + repeated-call consistency.

Preferred-index scoring is disabled in D, and D never silently falls back to A.

### 5.1 Native ABI validation

The controlled x86-64 harness rotated a 32-byte secret through argument indices 0–11, with 10 calls per position for each method.

| Method | Correct | Total | Accuracy |
|---|---:|---:|---:|
| A | 10 | 120 | 8.3% |
| D | 120 | 120 | 100.0% |

A was correct only when the rotated secret occupied its frozen hardcoded position. D was correct for all positions. This demonstrates argument-selection mechanics, not browser recovery.

### 5.2 Live OpenSSL/wolfSSL comparison

| Method | Attempts | Candidate selections | Exact matches | Decryptions | Complete | No candidate | False candidate |
|---|---:|---:|---:|---:|---:|---:|---:|
| A | 20 | 15 | 10 | 10 | 10 | 5 | 5 |
| D | 20 | 20 | 20 | 20 | 20 | 0 | 0 |

D completed 20/20 sessions (95% Wilson interval 83.89%–100.00%). A completed 10/20 (29.93%–70.07%). The result does not mean hardcoded positions always fail: A succeeded on the frozen wolfSSL layouts and failed on the frozen OpenSSL layouts. D removed that target-specific assumption in this controlled comparison.

## 6. Firefox/NSS results

| Dataset | Attempts | Exact comparison | Authenticated decryption | Complete recovery | Interpretation |
|---|---:|---:|---:|---:|---|
| TLS 1.2 final | 30 | 30/30 | 30/30 | 30/30 | Principal sealed-forensics result |
| TLS 1.3 strict regression | 5 | 5/5 | 5/5 | 5/5 | Sealed chronology and exact-reference regression |
| TLS 1.3 accepted historical final | 90 | Not measured | 90/90 | 90/90 | Preserved functional evidence; not upgraded to an exact-match claim |

The historical TLS 1.3 final campaign remains at commit `e0104374f113fd00a8f03bcadce46573b71e5951` with 90/90 valid case manifests and a clamped 95% Wilson interval of 95.91%–100.00%. It is not repeated and is not retroactively described as having server-reference equality. The strict 5/5 regression provides the newer sealed/exact chronology for TLS 1.3.

## 7. Negative controls

All 8/8 final TLS 1.2 negative controls passed:

1. no key-log candidate;
2. random same-length secret;
3. one-bit modified secret;
4. correct secret with wrong ClientHello random;
5. Frida diagnostic text treated as key material;
6. correct candidate on the wrong TCP stream;
7. unsupported NSS SHA-256/Build ID;
8. multiple fingerprint matches.

The positive sanity control recovered both the exact request path and response marker. These controls show that length, entropy, diagnostic output, or a correct secret without correct connection association is not sufficient.

## 8. Visual evidence

`FIREFOX-NSS-TLS12-VISUAL-EVIDENCE-001` is a separate supporting case. It records a real visible Firefox session on Xvfb, a localhost-only x11vnc endpoint, four 1280×800 stage screenshots, and an MP4. Its authoritative verification record reports: acquisition sealed `true`, exact server match `true`, TShark decryption `true`, and status `Eligible and fully recovered`.

The GUI is not part of the 30-session statistical dataset. PCAP, Frida events, server events, exact comparison, TShark output, and manifests remain authoritative.

## 9. Evidence integrity and secret handling

| Evidence set | Manifest result |
|---|---:|
| V4 freeze | valid |
| ABI final | valid |
| Live A/D campaign | valid (40/40 session manifests) |
| Firefox TLS 1.2 campaign | valid (30/30 session manifests) |
| Preserved Firefox TLS 1.3 final | valid (90/90 case manifests) |
| TLS 1.3 strict regression | valid |
| Final controls | valid |
| Visual case | valid |

Raw candidates and server references remain only in owner-readable private evidence files. Transcripts and reports expose case IDs, hashes, indices, lengths, scores, classifications, and non-secret metrics—not raw TLS secrets. Long-hex scans of public summaries, transcripts, reports, and visual artifacts found no secret-length material.

## 10. What changed from the earlier plan and report

The earlier report correctly marked Firefox TLS 1.2, live ranker evaluation, Ghidra detection, and real GUI evidence as incomplete. V3 closes those gaps while intentionally narrowing other work:

| Earlier direction | V3 decision |
|---|---|
| A–D ablation | Keep A versus full D only; B/C remain historical exploratory evidence |
| 160 live sessions | Use 40 fixed A/D sessions across two libraries and two protocols |
| 90 new Firefox TLS 1.2 sessions | Use 30 principal sessions (3 × 10) with stricter exact-reference chronology |
| Operator-effort study | Removed from required claims |
| Repeat accepted TLS 1.3 90-session campaign | Preserve unchanged; add a strict 5-session regression |
| GUI as evidence source | One supporting case only; machine evidence remains authoritative |

This is a deliberate scope correction, not an attempt to hide unfinished work. Excluded exploratory evidence remains labelled and preserved.

## 11. Limitations

- Firefox hooks and fingerprints are specific to Firefox 136.0.2 and the frozen NSS binaries.
- Experiments use a controlled localhost server, fixed cipher/profile policy, and one connection per case.
- Results do not demonstrate extraction from arbitrary remote machines or non-consenting targets.
- D is evaluated against A in these frozen targets; it is not proof that the scoring rules generalize to every TLS implementation or architecture.
- The TLS 1.3 90-session campaign provides functional validation but not exact server-reference equality; only the strict regression uses the final exact chronology.
- A 30/30 result still has uncertainty: its 95% Wilson lower bound is 0.8865.

## 12. Reproducibility and audit locations

```text
Freeze:        cases/FROZEN-BASELINE-V4/
ABI:           results/ARG-RANKER-ABI-FINAL-001/
Live A/D:      cases/ARG-RANKER-LIVE-FINAL-001/
Firefox TLS12: results/FIREFOX-NSS-TLS12-FINAL-MEASURED-001/
Controls:      cases/NEGATIVE-CONTROLS-FIREFOX-NSS-TLS12-FINAL-001/
Visual case:   cases/FIREFOX-NSS-TLS12-VISUAL-EVIDENCE-001/
TLS13 final:   results/FIREFOX-NSS-TLS13-FINAL-MEASURED-001/
TLS13 strict:  results/FIREFOX-NSS-TLS13-REGRESSION-STRICT-001/
```

Verify any evidence directory from inside it with:

```bash
sha256sum -c --quiet evidence-manifest.sha256
```

The machine-readable non-secret v3 tables are in `results/TLSKEYHUNTER-V3-SUMMARY/`.

## 13. Defensible thesis claim

> This thesis extends TLSKeyHunter's static-to-dynamic workflow with a controlled live-memory acquisition and verification pipeline. TLS derivation candidates were acquired from active processes, sealed before verification, compared byte-for-byte with an independently generated server reference, and validated through authenticated recovery of controlled application traffic. A full explainable ranker was additionally compared with the original hardcoded argument-position approach under frozen experimental conditions.

The claim is limited to the authorized frozen laboratory targets and the evidence described above.
