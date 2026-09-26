# TLSKeyHunter Upstream Provenance Record

**Project:** Improving the Robustness of Static-to-Dynamic TLS Key Extraction  
**Record status:** Controlled thesis provenance document  
**Prepared:** 2026-08-30  
**Research environment:** Authorized university-controlled localhost/VPS laboratory

## 1. Purpose

This document prevents the original TLSKeyHunter work from being confused with the thesis extension. The upstream project is the research foundation. It must remain visible, attributed, and unmodified in the historical record. Later thesis code may extend or wrap it, but must not be presented as an original implementation of the upstream ideas.

## 2. Upstream project identity

| Field | Recorded value |
|---|---|
| Project name | TLSKeyHunter |
| Repository | <https://github.com/monkeywave/TLSKeyHunter> |
| Paper named by the upstream README | *All Your TLS Keys Are Belong to Us: A Novel Approach to Live Memory Forensic Key Extraction* |
| Version printed in the upstream README example | `0.9.4.0` |
| Upstream commit used to create the research copy | **Pending exact verification; do not infer this from a later thesis commit** |
| Local frozen thesis commit for the accepted v2 evidence | `e0104374f113fd00a8f03bcadce46573b71e5951` |
| Frozen v2 branch | `codex/plan-v2-completion` |
| Gap-closure branch | `codex/v2-gap-closure` |

The commit `e0104374...` identifies the thesis experiment state, not necessarily the original upstream revision. Before public submission, the exact upstream base commit must be recovered from Git history and added here.

## 3. Work attributed to the upstream project

Based on the supplied upstream README, the following concepts and artifacts belong to TLSKeyHunter's original authors unless a file-level history proves otherwise:

- the core Ghidra-based `TLSKeyHunter.java` analysis;
- identification of TLS PRF/HKDF functions using TLS-related string references;
- generation of key-derivation fingerprints and Frida-compatible byte patterns;
- the library-specific Frida extraction approach under `tlsKeyExtraction/`;
- the TLS-KeyGround ground-truth dataset and its validation purpose;
- the Java bytecode analyzer under `tlskeyhunterforjava/`;
- the real-world example collection;
- the `network_decryption/randomInverse.py` approach for associating an extracted secret with a client random and generating Wireshark-compatible key-log material;
- the general static-analysis-to-dynamic-instrumentation workflow.

These items must not be claimed as thesis inventions.

## 4. Thesis-added extension areas

The controlled thesis work extends the upstream foundation in these bounded areas:

- a candidate argument-ranking module (`arg_ranker`) and its deterministic tests;
- a comparison between the original hardcoded-position behavior (configuration A) and the full ranker (configuration D);
- native x86-64 argument-position test infrastructure;
- controlled OpenSSL and wolfSSL runtime evaluations;
- version-pinned Firefox 136.0.2/NSS TLS 1.2 and TLS 1.3 hooks and runners;
- independent candidate/PCAP pair testing with authenticated TShark decryption and exact request/response recovery;
- strict fingerprint, binary-hash, Build-ID, and unique-match gates;
- evidence manifests, frozen experiment metadata, negative controls, non-secret summaries, and teaching-mode terminal transcripts.

The candidate-to-client-random association is an upstream concept. The thesis contribution is the controlled automation, version-specific implementation, strict validation, and evidence framework around that association—not the first proposal of the association concept.

## 5. Preservation policy

The following preservation rules are mandatory:

1. Do not delete, rename to conceal, or rewrite upstream files merely because they are outside the final experiment scope.
2. Keep original Git history and upstream attribution wherever technically possible.
3. Place new work on a clearly named thesis branch and identify thesis commits separately.
4. Treat accepted evidence and frozen baselines as immutable.
5. If an upstream algorithm or hook is not evaluated, describe it as **present but outside the selected evaluation scope**.
6. Preserve failed and superseded thesis cases; classify them instead of erasing them.
7. Never publish raw TLS secrets, private keys, or secret-bearing key-log files.

## 6. Redistribution and notice caution

The supplied README states that the project is intended for academic and research purposes and that commercial use is prohibited. This document does not determine the repository's complete legal licensing status. Before publishing a modified repository or redistributing upstream artifacts:

- inspect the repository for the exact license and notices at the pinned upstream commit;
- retain copyright, authorship, citation, and license notices;
- cite the upstream paper and repository in the thesis;
- seek permission if the available license does not clearly authorize the planned redistribution.

## 7. Required provenance checks before submission

- [ ] Record the exact upstream commit SHA from which the thesis repository was derived.
- [ ] Record the upstream remote URL from Git configuration.
- [ ] Record the thesis branch and final thesis commit.
- [ ] Verify that the upstream README and notices remain present.
- [ ] Verify that every thesis-added file is identified in the contribution inventory.
- [ ] Verify that no thesis statement claims upstream mechanisms as novel work.
- [ ] Verify the applicable license/permission terms at the exact upstream revision.

## 8. Recommended thesis attribution text

> This research builds on TLSKeyHunter, introduced in *All Your TLS Keys Are Belong to Us: A Novel Approach to Live Memory Forensic Key Extraction*. TLSKeyHunter provides the foundational Ghidra-based key-derivation fingerprinting and library-specific dynamic instrumentation workflow. The present work evaluates a bounded robustness extension: ranked runtime argument selection, version-pinned Firefox/NSS support, and a controlled evidence and validation pipeline. Existing TLSKeyHunter mechanisms are attributed to the original authors and are not claimed as contributions of this thesis.

