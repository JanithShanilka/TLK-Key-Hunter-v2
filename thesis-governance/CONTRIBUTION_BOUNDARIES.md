# TLSKeyHunter Thesis Contribution Boundaries

**Purpose:** Define exactly what may and may not be claimed as the thesis contribution.  
**Applies to:** Thesis text, figures, presentations, repository documentation, and oral defense.

## 1. One-sentence boundary

The thesis does not invent TLSKeyHunter; it builds on TLSKeyHunter and evaluates a bounded robustness extension consisting of full ranked argument selection, version-pinned Firefox/NSS support, and stricter controlled evidence and verification.

## 2. Ownership and contribution matrix

| Area | Upstream TLSKeyHunter foundation | Thesis extension | Safe thesis wording |
|---|---|---|---|
| Static analysis | Ghidra-based discovery of TLS PRF/HKDF functions and key-derivation fingerprints | Reproduce and freeze provenance for selected pinned binaries; require a unique fingerprint match | “We reproduced and applied TLSKeyHunter's fingerprinting workflow to the pinned targets.” |
| Dynamic instrumentation | Library-specific Frida hook approach | Version-specific controlled hooks, gates, structured events, and failure behavior | “We extended the hook set and validation logic for the selected versions.” |
| Argument selection | Existing hooks may rely on fixed per-hook argument positions | `arg_ranker` configuration D and controlled A-versus-D evaluation | “We designed and evaluated a ranked alternative to fixed argument-position selection.” |
| Ground truth | TLS-KeyGround and the upstream validation concept | Exact development equality plus experiment-specific server ground truth | “We used independent ground truth during development.” |
| Client-random association | `randomInverse.py` already associates secrets with a client random | Independently test each candidate/random pair using authenticated TShark decryption and exact markers | “We automated and strengthened validation of candidate-to-PCAP associations.” |
| Firefox/NSS | General workflow originates upstream | Pinned Firefox 136.0.2/NSS TLS 1.2 and TLS 1.3 implementations and campaigns | “We implemented and evaluated version-pinned Firefox/NSS cases.” |
| Evidence control | General research artifacts exist upstream | Immutable case IDs, manifests, freezes, controls, transcripts, and non-secret summaries | “We added a reproducible evidence-control layer for the selected experiments.” |
| Usability | No thesis ownership claim | Timed effort study excluded from required scope | Do not claim measured usability or analyst-effort improvement |

## 3. Thesis contributions that may be claimed

Subject to completion and evidence verification, the thesis may claim:

1. An explainable full ranker that combines memory readability, expected length, entropy/zero-count characteristics, and cross-call consistency.
2. A controlled comparison of that ranker with the original hardcoded-position baseline in a native x86-64 harness.
3. A reduced end-to-end live comparison across selected OpenSSL and wolfSSL TLS 1.2/TLS 1.3 sessions.
4. A version-pinned Firefox 136.0.2/NSS TLS 1.2 proof-of-concept, alongside preserved accepted TLS 1.3 evidence.
5. Independent candidate/PCAP pair validation using authenticated decryption and exact request/response markers.
6. Strict binary/fingerprint gating and fail-closed behavior for zero or multiple pattern matches.
7. A reproducible evidence framework using manifests, frozen configurations, controls, classified failures, and non-secret terminal transcripts.

Each claim must be tied to a named evidence identifier and must state the controlled experimental context.

## 4. Claims that must not be made

Do not claim:

- authorship or invention of TLSKeyHunter;
- invention of Ghidra-based TLS PRF/HKDF fingerprint discovery;
- invention of Frida-based runtime TLS key extraction;
- invention of secret-to-client-random association;
- revalidation of every TLSKeyHunter target, library, operating system, or architecture;
- universal superiority or universal correctness of ranker D;
- production readiness, stealth, safety on arbitrary targets, or resistance to all compiler/version changes;
- population-level usability or analyst-effort improvement;
- that excluded, failed, or superseded experiments succeeded;
- that a plausible candidate is correct without exact equality or authenticated decryption;
- that Firefox/NSS TLS 1.2 has final coverage until all 30 planned final attempts are present and classified;
- that public artifacts contain the complete evidence if secret-bearing files remain private.

## 5. Result-label vocabulary

Use these labels consistently:

| Label | Meaning |
|---|---|
| Development | Used to correct implementation; may use internal ground truth |
| Pilot | Tests readiness before freezing; not the final statistical dataset |
| Regression | Confirms accepted behavior remains intact after changes |
| Final | Executed against a frozen configuration with all planned attempts classified |
| Accepted | Meets every stated acceptance requirement |
| Failed | Attempted but did not meet the acceptance requirements |
| Superseded | Replaced after a documented implementation or protocol correction |
| Excluded | Intentionally outside the final required scope |
| Supporting evidence | Helpful for inspection, but not authoritative for correctness |

GUI screenshots and video are supporting evidence. PCAPs, Frida events, server logs, exact marker recovery, and manifests are authoritative.

## 6. Required claim-to-evidence map

| Intended claim | Minimum evidence |
|---|---|
| Existing Firefox/NSS TLS 1.3 reproducibility | Preserved 90-session campaign, valid manifests, frozen v2 hashes, 8/8 controls, 5/5 regression |
| Native ranker improvement | `ARG-RANKER-ABI-FINAL-001`, all 240 A/D observations, exact equality, failures retained |
| Live A/D feasibility | `ARG-RANKER-LIVE-FINAL-001`, all 40 sessions attempted and classified |
| Firefox/NSS TLS 1.2 proof-of-concept | pilot 5/5, `FROZEN-BASELINE-V4`, all 30 final attempts classified, final controls 8/8 |
| Static fingerprint provenance | Ghidra version/path/hash, binary SHA-256 and Build ID, offset, masked pattern, match count, hook mapping |
| Visual operation | `FIREFOX-NSS-TLS12-VISUAL-EVIDENCE-001`; screenshots/video plus authoritative case evidence |

## 7. Suggested thesis language

### Method statement

> We used TLSKeyHunter as the upstream static-to-dynamic extraction foundation. Our experimental extension replaced a fixed argument-position assumption with a full, explainable ranking configuration and added version-pinned Firefox/NSS support plus strict evidence controls. The comparison was deliberately limited to the original hardcoded baseline (A) and the full ranker (D).

### Novelty statement

> The contribution is not the original TLSKeyHunter fingerprinting or client-random association concept. It is the design and controlled evaluation of the ranking extension, the selected Firefox/NSS implementation, and the fail-closed, independently verified evidence pipeline.

### Limitation statement

> Results apply to the frozen binaries, protocols, architecture, and controlled workloads studied. They demonstrate proof of concept and do not establish universal library coverage, production readiness, or population-level usability.

### Result statement template

> In `[EVIDENCE-ID]`, configuration D recovered `[x/y]` planned observations/sessions under the frozen conditions, compared with `[a/b]` for configuration A. All failures and no-candidate outcomes remained in the denominator, and correctness required exact equality or authenticated recovery of both controlled application markers.

## 8. Repository separation rules

- Preserve upstream source and notices in place.
- Add thesis work in separately identifiable files and commits.
- Never rewrite old accepted cases or `FROZEN-BASELINE-V3`.
- Store public, sanitized summaries separately from owner-readable secret evidence.
- Keep exploratory B/C results, failed cases, and superseded runs labelled but outside the final A/D tables.
- Create `FROZEN-BASELINE-V4` only after code, policies, targets, and reference evidence are final.
- Refuse to overwrite any existing evidence identifier.

## 9. Final authorship audit

Before submission, check every sentence using “we developed,” “we introduced,” “novel,” or “first.” For each one:

1. identify the exact thesis-added artifact;
2. identify the evidence that validates it;
3. check that the upstream README/paper did not already describe the concept;
4. narrow or remove the sentence if ownership or novelty is uncertain;
5. cite the upstream paper and repository where the dependency first appears.

If provenance is uncertain, the safe wording is “we applied,” “we extended,” “we reproduced,” or “we evaluated,” followed by the exact bounded extension.

