# Firefox saved-memory extraction experiment

Status: original proposed protocol, retained for provenance. See SAVED_MEMORY_RESULT.md for completed pilot results and the separately reported packet-assisted selection step.
Prepared: 2026-09-27. Initial target: the existing controlled Linux x86-64 Firefox/NSS TLS 1.2 lab.

## Research question

Can an extractor, given only a saved Firefox process-memory image and public target metadata, independently select the correct TLS 1.2 master secret? Does that selected secret exactly match an isolated server reference and decrypt the intended captured connection?

This is a new offline experiment. Previously recorded Frida recovery percentages do not measure it.

## Acquisition and evaluation sequence

1. Freeze Firefox/NSS versions, target hashes, extraction rules, timing conditions and scoring policy. Use a fresh profile and one controlled TLS connection per case.
2. Start packet capture and a controlled server. The server exports a private reference independently; the browser must not export keys.
3. Generate a known request/response marker and keep the connection active. Verify the negotiated protocol from the handshake, rather than a filename or the TLS record-layer legacy version.
4. Identify the Firefox process that owns the connection and loaded NSS libraries. Firefox uses multiple processes; do not assume the visible browser's PID is the correct target. Record how the PID was selected.
5. Capture an ELF core file using GDB/gcore. Record capture start/end, mappings, registers, loaded module identities, capture settings and omitted/unreadable regions. Debugger acquisition may briefly pause the process; it is not an instantaneous, non-intrusive snapshot.
6. Hash the dump and metadata. Keep them private. The extractor runs in a separate environment with read-only dump access, no target process, no reference file and no target key-log file.
7. Generate candidates from captured memory using a documented, version-pinned structural method. Rank and fix the output before opening any reference or testing decryption. Record ties and abstentions explicitly.
8. Seal the selected output and ranked candidate list. Only the verifier now reads the server reference and PCAP.
9. Compare the selected TLS 1.2 master secret byte-for-byte against the reference for the controlled connection, then decrypt the PCAP using only the selected extracted secret. Require both exact request and response markers.
10. Run negative controls and retain every attempted case in the denominator.

GDB documents core generation, mapping filters and excluded mappings at:
https://sourceware.org/gdb/current/onlinedocs/gdb.html/Core-File-Generation.html

## Prevent contamination

- Disable the current Frida TLS 1.2 hook during primary memory capture. It calls `PK11_ExtractKeyValue` and `PK11_GetKeyData`; those calls can materialize a readable copy and would confound a claim about unassisted Firefox memory.
- Do not enable target `SSLKEYLOGFILE`, import a key-log file into Firefox, or inject known secret bytes.
- Keep the server reference outside the extractor's accessible filesystem. Prefer a separate controlled server environment for a demonstrable separation.
- Do not use the reference secret to locate candidates or tune ranking on final evaluation cases.
- A hash is an integrity record, not by itself proof that code never accessed a reference. Preserve access boundaries, commands and chronology too.

## Relationship to arg_ranker

The current arg_ranker consumes argument pointers at observed calls. A generic core dump captured after the handshake does not supply that argument list. Therefore an offline candidate-discovery layer is required before its useful heuristics can be adapted.

The first pilot must determine whether the master secret remains available as a readable NSS object in the captured mappings. Then implement and freeze the corresponding candidate enumerator; a reference-guided presence audit may aid development, but must be kept separate from blind extraction evaluation.

Length, readability and entropy can filter candidates, but do not establish that a buffer is a TLS secret. A readable 48-byte window is not necessarily an allocated 48-byte secret. A full memory image can contain many equally plausible random buffers.

Call-consistency and before/after-call features are unavailable in a single arbitrary snapshot. Disable them and label the method as an offline adaptation; do not claim unchanged configuration D. If repeated snapshots are evaluated, specify that separate input condition and its extra acquisition cost.

An alternative is a dump captured at a derivation breakpoint with saved argument context. That is an instrumented, event-triggered experiment and should have its own results; it must not be substituted for an arbitrary post-handshake dump without disclosure.

## Metrics

- Top-1 exact recovery: attempts where the independently selected secret equals the reference / all attempted cases.
- End-to-end session recovery: attempts with successful acquisition, offline selection, exact equality and intended traffic decryption / all attempted cases.
- Top-k candidate recall: attempts where the true secret occurs in the frozen first k candidates / all attempted cases. Declare k before final evaluation; ties must not be broken using the reference.
- Extraction time, dump size, candidate count and abstention/ambiguity rate.
- Secondary presence audit: after extraction output is sealed, a separate verifier can search for the reference bytes inside captured memory segments. This measures literal-byte presence, not extractor success or proof of the secret's original role.
- Conditional recovery among dumps with verified literal-byte presence may also be reported, alongside the all-attempt rate. Absence of literal bytes does not rule out wrapped, fragmented or transformed representations.

Hamming distance is a diagnostic only. For a 48-byte TLS 1.2 master secret there are 384 bits, and success requires zero differing bits. Never present `1 - differing_bits/384` as cryptographic recovery accuracy. Unrelated random buffers can agree on about half their bits by chance.

## Pilot and final study

Begin with an exploratory feasibility pilot on one pinned Firefox/NSS build and TLS 1.2. Establish process selection, connection lifetime, capture coverage, secret persistence and candidate structure before promising a recovery percentage.

After development, freeze a fresh final evaluation design. Capture timing should be fixed or explicitly stratified (for example, during an active connection versus after closure); do not select favorable dump times after seeing the reference. Preserve acquisition failures, timeouts, missing candidates, ambiguity, false selections and failed decryptions.

A later TLS 1.3 experiment must report each required secret label and epoch independently, plus session recovery. Existing TLS 1.3 instrumentation results do not establish offline dump extraction, key-update coverage, resumption coverage or 0-RTT coverage.

## Current implementation and environment status

- Existing live extraction source and summaries have been inspected.
- No offline core-file candidate enumerator or final offline ranker has been validated.
- No live-memory dump was captured in this planning step.
- The configured research SSH host at 89.167.33.8 timed out during a read-only readiness check. Its availability/address must be resolved before the controlled pilot can run.
- This protocol is local working documentation; it does not change or relabel the published historical results.
