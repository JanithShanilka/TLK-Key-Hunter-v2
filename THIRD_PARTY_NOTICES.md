# Upstream attribution and license scope

This project builds on TLSKeyHunter: <https://github.com/monkeywave/TLSKeyHunter>.

Upstream paper: *All Your TLS Keys Are Belong to Us: A Novel Approach to Live Memory Forensic Key Extraction*.

The supplied upstream README is preserved verbatim at `docs/UPSTREAM_README.md`. It states: "This project is intended for academic and research purposes only. Commercial use is prohibited."

`TLSKeyHunter.java`, `MinimalAnalysisOption.java`, `custom_log4j.xml`, and `network_decryption/randomInverse.py` were copied unchanged from the user-supplied TLSKeyHunter-main archive. Their hashes are recorded in `docs/UPSTREAM_FILES.json`. The OpenSSL/wolfSSL hooks, ground-truth clients, Firefox/NSS extraction work and Ghidra wrapper contain or derive from upstream work. Preserve their existing comments and attribution.

The exact upstream base commit and complete applicable permissions have not been established from the local archive. No broader license grant for upstream content is asserted here. The root MIT license covers only original contributions for which the named copyright holder has the right to grant it; it does not supersede upstream notices or third-party rights.

See `thesis-governance/UPSTREAM_PROVENANCE.md` and `thesis-governance/CONTRIBUTION_BOUNDARIES.md` for the historical attribution record and research contribution boundaries.
