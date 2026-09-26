# TLSKeyHunter thesis extension

Research snapshot for **Improving the Robustness of Static-to-Dynamic TLS Key Extraction** by Janith Shanilka Geekiyanage Don (UCSC).

This work extends [TLSKeyHunter](https://github.com/monkeywave/TLSKeyHunter), described in *All Your TLS Keys Are Belong to Us: A Novel Approach to Live Memory Forensic Key Extraction*. The original project supplies static PRF/HKDF discovery, fingerprints, library-specific Frida extraction, and client-random association. These mechanisms are attributed to the upstream authors.

## Current status

This is an import of the locally available August 2026 implementation and research artifacts, published in September 2026. It is a **partial research snapshot**, not a complete export of the original Linux laboratory or its Git history. Historical experiment commit IDs in reports are preserved references; those commits are not included in this repository history.

The extension provides an explainable `arg_ranker`, OpenSSL/wolfSSL hook integration, pinned Firefox 136.0.2/NSS hooks, controlled experiment runners, candidate sealing before independent verification, and non-secret result summaries.

The final evaluation scope is A (hardcoded argument selection) versus D (full ranker) on OpenSSL/wolfSSL, with separate Firefox/NSS validation. The Interim 1 plan's s2n-TLS/Schannel evaluation, timed analyst-effort study, and final four-way ablation are not completed by this snapshot. Firefox recovery is not evidence that its version-specific argument selection was automated by the ranker.

## Start here

| Location | Contents |
| --- | --- |
| [TLSKeyHunter_REPORT_v3.md](TLSKeyHunter_REPORT_v3.md) | Latest local research report and limitations |
| [report.md](report.md) | Earlier report retained as historical context |
| [tlsKeyExtraction/](tlsKeyExtraction/) | Ranker and modified OpenSSL/wolfSSL hooks |
| [lab/](lab/) | Native ABI, live comparison, Firefox, baseline and evidence runners |
| [tests/](tests/) | Ranker and forensic-workflow regression tests |
| [results/](results/) | Imported v3 summary tables and session summaries |
| [evidence-summaries/](evidence-summaries/) | Earlier frozen metadata and summarized controls |
| [thesis-governance/](thesis-governance/) | Recorded scope, attribution and contribution boundaries |
| [visual-evidence/](visual-evidence/) | Supporting screenshots and recording |
| [docs/TLSKeyHunter_Explained.docx](docs/TLSKeyHunter_Explained.docx) | Existing explanatory document |
| [docs/UPSTREAM_README.md](docs/UPSTREAM_README.md) | Preserved original README and notices |
| [docs/SNAPSHOT.md](docs/SNAPSHOT.md) | Import provenance, omissions and verification boundaries |

## Recorded results

| Experiment | Baseline A | Full ranker D |
| --- | --- | --- |
| Native argument-position benchmark | 10/120 correct | 120/120 correct |
| OpenSSL/wolfSSL live complete recovery | 10/20 | 20/20 |

The separate Firefox/NSS TLS 1.2 campaign records 30/30 complete recoveries. These are **previously recorded laboratory results**, not experiments rerun during publication. Raw private acquisition/reference files and full case manifests are not supplied, so this checkout alone cannot independently revalidate every recorded result. Results apply to the frozen targets and controlled workloads described in the report.

## Run the local tests

With Node.js and Python 3 installed, from the repository root:

```sh
node tests/test_arg_ranker.js
python3 tests/test_live_forensics.py
```

Publication checks passed: 12 JavaScript ranker tests and 10 Python regression tests. The Python suite includes source-order assertions and does not replace live end-to-end validation.

## Laboratory execution

The live experiments require the original Linux x86-64 lab setup: matching target binaries, Ghidra, Frida and its Python bindings, TShark/packet-capture tooling, OpenSSL/wolfSSL clients, and the pinned Firefox/NSS build. The Firefox runner also imports `websockets`. Inspect the recorded tool versions, runner arguments and fixed paths before use. The original prebuilt targets, private certificates/keys, profiles, and full evidence store are not bundled.

`ghidra_analysis.sh` is accompanied by the original Ghidra Java sources from the supplied upstream archive. Their exact upstream revision remains unverified. The historical `phase18a_firefox_nss_runner.remote-unfinished-20260829.py` is retained for audit context; use `phase18a_firefox_nss_runner.py` for the current local runner.

Use only researcher-controlled targets and captures. Generated case directories can contain TLS secrets and must remain private; `.gitignore` excludes them by default.

## Attribution and license scope

See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md). The repository's MIT license applies only to original contributions for which the named copyright holder can grant those rights. It does not relicense upstream or third-party code. The supplied upstream README states academic/research use and prohibits commercial use; that notice is preserved. Exact upstream commit and redistribution permissions remain recorded provenance gaps, not resolved claims.
