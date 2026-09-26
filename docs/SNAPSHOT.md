# Publication snapshot — 2026-09-27

This snapshot imports the locally available `TLSKeyHunter-work` source tree, `TLSKeyHunter_REPORT_v3.md`, v3 result summaries, supporting visual evidence, and the existing explanatory Word document. It is not a recovered copy of the complete remote research host.

## Layout mapping

- `TLSKeyHunter-work/` contents become the repository root.
- `TLSKeyHunter_v3_results/` becomes `results/`.
- `TLSKeyHunter_visual_evidence/` becomes `visual-evidence/`.
- The explanatory Word document is under `docs/`.
- A minimal set of original static-analysis and association source files is restored from the supplied upstream archive; `UPSTREAM_FILES.json` identifies these files and their SHA-256 hashes.

Reports and frozen metadata are preserved rather than rewritten to imply a new experiment. Historical absolute paths, commit IDs and evidence paths refer to the laboratory at experiment time. Some referenced files and tools are absent from this partial snapshot. Stored historical manifests can refer to private or missing artifacts and are not a manifest of this Git checkout.

## Intentionally omitted

- Python bytecode, caches, scratch rendering files and duplicate ZIP archives.
- Raw TLS secrets, private keys, packet captures and complete private case directories.
- Large upstream binary datasets and dependencies, which must be obtained and validated separately.
- Two older pilot screenshots; the later dedicated visual evidence set is included.

## Checks performed during publication

- 12 JavaScript ranker tests passed.
- 10 Python forensic-workflow regression tests passed.
- Text files and Word XML were scanned for private-key blocks, literal TLS key-log entries and common credential-token formats, with no matches.
- The four final supporting screenshots were visually inspected.

These checks do not constitute a rerun of the Linux laboratory, independent verification of private evidence, or proof that heuristic secret scanning detects every possible confidential value.

## Remaining research gaps

The current work records a revised OpenSSL/wolfSSL A-versus-D evaluation and Firefox/NSS proof of concept. It does not establish the original Interim 1 s2n-TLS/Schannel evaluation, measured analyst-effort reduction, a final full four-way ablation, universal argument discovery, or complete reproduction from a fresh machine. Exact upstream provenance also remains unresolved. The existing reports distinguish historical, exploratory and final datasets.
