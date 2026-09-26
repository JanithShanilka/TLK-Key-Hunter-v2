# TLSKeyHunter Thesis Scope and Experiment Contract

**Scope version:** 1.0  
**Effective date:** 2026-08-30  
**Status:** Governing scope for remaining gap-closure work

## 1. Thesis objective

This thesis evaluates whether a small, explainable candidate-ranking extension improves the robustness of TLS key extraction when an observed function's relevant argument is not reliably located at one hardcoded position. It also demonstrates the extension in a controlled, version-pinned TLS laboratory with reproducible evidence.

This is a proof-of-concept and controlled experimental evaluation. It is not a claim of production readiness, universal TLS-library support, general analyst usability, or authorization to inspect third-party systems.

## 2. Research questions

The final work addresses three bounded questions:

1. In a controlled native x86-64 harness, how does full ranked selection compare with the original hardcoded argument-index behavior when the true value rotates through positions 0–11?
2. In controlled OpenSSL and wolfSSL TLS 1.2/TLS 1.3 sessions, can both methods be evaluated end to end using exact evidence and authenticated decryption?
3. Can the TLSKeyHunter workflow be extended reproducibly to pinned Firefox 136.0.2/NSS TLS 1.2 while preserving the already accepted TLS 1.3 result?

## 3. Selected methods

Only two ranker configurations are required in the final comparison:

| ID | Method | Final role |
|---|---|---|
| A | Original per-hook hardcoded argument index | Baseline |
| D | Readability + expected length + entropy/zero-count + consistency | Proposed full ranker |

Configurations B and C remain useful exploratory pilot observations. They are not required final algorithms, will not receive additional final experiment runs, and must not be mixed into the confirmatory A-versus-D result.

## 4. In-scope targets and environment

- authorized VPS and localhost research targets only;
- Linux x86-64;
- Ghidra static fingerprint provenance;
- Frida dynamic instrumentation;
- OpenSSL and wolfSSL for the live A-versus-D comparison;
- Firefox 136.0.2 with pinned NSS binaries;
- TLS 1.2 and TLS 1.3 under fixed protocol/cipher policies;
- TShark-based authenticated decryption;
- deterministic or frozen seeds where randomization is used;
- non-secret terminal teaching output and evidence manifests.

## 5. Explicitly outside the required scope

The following work is removed from the required completion gate. Existing artifacts are retained and honestly labelled; they are not deleted or hidden.

| Excluded item | Treatment |
|---|---|
| Final B and C ranker evaluations | Retain pilot data; no new final runs |
| Full four-configuration 160-session live ablation | Superseded by the reduced A/D live study |
| One-analyst timed effort study | Optional future work; no usability claim |
| Population-level usability conclusions | Prohibited by the study design |
| Repeating the accepted 90-session Firefox/NSS TLS 1.3 campaign | Do not repeat; preserve and reverify manifests |
| A new 90-session TLS 1.2 campaign | Superseded by a smaller proof-of-concept campaign |
| Revalidation of every upstream library and example | Outside selected evaluation targets |
| Internet or third-party target testing | Prohibited |
| Production deployment and stealth/evasion evaluation | Outside academic proof-of-concept scope |

## 6. Evidence already established

### Accepted frozen v2 evidence

- Firefox/NSS TLS 1.3 final campaign: 90/90 fully recovered sessions.
- Firefox/NSS TLS 1.3 final controls: 8/8 passed, with positive sanity recovery.
- All 90 case manifests were previously reported valid.
- Frozen v2 commit: `e0104374f113fd00a8f03bcadce46573b71e5951`.
- Existing eight `arg_ranker` tests and synthetic ablation passed.
- Controlled wolfSSL TLS 1.2 and TLS 1.3 baselines were accepted.

### Gap-closure evidence produced after v2

- Native ABI pilot: 480 observations recorded; A 10/120, B 10/120, C 21/120, D 120/120.
- Firefox/NSS TLS 1.2 development case achieved exact ground-truth equality and authenticated decryption.
- Ground-truth-free TLS 1.2 pilot completed 5/5 after independent candidate/random pair verification was corrected.
- TLS 1.2 pilot controls completed 8/8 with positive sanity recovery.
- TLS 1.3 regression completed 5/5 without repeating the accepted 90 sessions.

The post-v2 evidence remains subject to final manifest collation and inclusion in `FROZEN-BASELINE-V4`. Failed and superseded development cases remain part of the audit trail and are not counted as accepted results.

## 7. Minimum remaining completion set

The final thesis evidence should be completed in this order:

1. **Provenance closure:** record the exact upstream commit and complete the Ghidra mapping for the pinned NSS and selected live-library binaries.
2. **Native A/D final:** 12 argument positions × 10 calls × 2 methods = **240 observations**.
3. **Reduced live A/D study:** OpenSSL and wolfSSL × TLS 1.2 and TLS 1.3 × A and D × 5 independent sessions = **40 attempted sessions**.
4. **Representative GUI evidence:** one separate Firefox/NSS TLS 1.2 case with screenshots and MP4; supporting evidence only.
5. **Freeze V4:** include source, tools, binaries, fingerprints, policies, seeds, accepted pilot/control/regression references, and clean Git state.
6. **Firefox/NSS TLS 1.2 final proof-of-concept:** 3 runs × 10 attempted sessions = **30 attempted sessions**.
7. **Final TLS 1.2 controls:** all eight controls against a final accepted case, including positive sanity recovery.
8. **Report v3:** compare A with D, report every planned attempt, state exclusions and limitations, and preserve the old report unchanged.

The sample sizes above are a deliberate proof-of-concept scope reduction from the earlier gap-closure plan. They must be documented before final execution and must not be enlarged or reduced after seeing final outcomes without a separately explained protocol amendment.

## 8. Session acceptance contract

A recovered TLS session requires all of the following:

```text
controlled workload event
+ matching controlled server event
+ complete TLS handshake
+ relevant Frida event
+ unambiguous candidate/PCAP association
+ authenticated TShark decryption
+ exact request recovery
+ exact response marker recovery
+ valid evidence manifest
= recovered session
```

Plausible entropy, expected length, a readable pointer, or encrypted application data alone is not proof. A one-bit mismatch is incorrect.

Every planned attempt remains in the denominator. Failures and no-candidate results are classified, not discarded.

## 9. Stop conditions

Extraction or acceptance must stop when any of these occur:

- the binary hash or Build ID differs from the frozen target;
- a fingerprint has zero or multiple matches;
- the relevant structure is unreadable or has an unexpected length;
- a candidate cannot be associated unambiguously with the controlled PCAP;
- authenticated decryption does not recover both exact markers;
- the evidence identifier already exists;
- final code or configuration differs from `FROZEN-BASELINE-V4`;
- raw secrets would be exposed in a public artifact.

## 10. Reporting rules

- Report results as controlled proof-of-concept evidence.
- Distinguish development, pilot, regression, final, failed, excluded, and superseded cases.
- Do not claim that every upstream TLSKeyHunter target was revalidated.
- Do not claim that ranker D is universally correct.
- Do not claim analyst-effort or usability improvements without the excluded effort study.
- Do not claim the client-random association concept as novel.
- Report confidence intervals with bounds clamped to `[0,1]`.
- Keep raw key material only in owner-readable private evidence on the lab host.

## 11. Scope-change rule

Any later scope change must be written before running the affected final experiment and must state:

- the change;
- the reason;
- whether it was made before or after seeing relevant results;
- the affected identifiers and sample sizes;
- the impact on claims and comparability.

No excluded task becomes required merely because its old code or pilot evidence remains in the repository.

