# TLS 1.2 repeatability campaign — completed

Twenty fresh Firefox sessions were captured over about 3 hours 11 minutes, ten minutes apart. The first attempt hit an orchestration permission failure. All 19 continuation sessions completed automatically, recovering the exact secret and decrypting both controlled application markers. The original failed attempt was successfully reanalyzed after the permissions fix using its existing dump; no replacement capture was made.

| Measure | Observed result |
|---|---:|
| Initial unattended outcome, all attempted sessions | 19/20 (95%) |
| Continuation after permission repair | 19/19 (100% observed) |
| Original failed attempt, separate post-repair reanalysis | 1/1 successful |
| Eventual exact recovery across all captured sessions, including reanalysis | 20/20 |
| Unique selection by memory-only ranking, continuation | 0/19 (ties; abstained) |
| Reference secret included in memory candidates, continuation | 19/19 |
| Unique packet-validation winner, continuation | 19/19 |
| One-bit-corrupted reference rejected, continuation | 19/19 |
| Campaign dump/profile cleanup recorded | 20/20 including repaired first attempt |

The percentages are observed rates in this fixed lab setup, not estimates that establish universal reliability. Keep the 95% initial unattended outcome separate from eventual recovery after manual repair. The 19-session continuation contains 15 cases with five candidates and four with four candidates: 91 candidate checks, 19 passes and 72 failures to recover the required request/response pair. These candidate checks are not independent connection experiments. All recovered secrets had zero differing bits against the independent reference. Median continuation runtime was 47.62 seconds.

Campaign A began at 2026-09-27 19:08:43 UTC; continuation B ended at 2026-09-27 22:19:41 UTC (2026-09-28 00:38:43 to 03:49:41 Asia/Colombo). A preserved its ranking-launch permissions failure. Its subsequent result is in `campaigns/TLS12-REPEAT-20260928-A/post-repair-analysis.json`. Campaign B contains the remaining 19 fresh cases. Capture/extractor/verifier script hashes match across the two campaign manifests; only the orchestration runner changed.

## Interpretation

The successful recovery was repeatable across fresh sessions under the tested conditions; it was not confined to one memory dump. Memory-only ranking still could not choose a unique winner. The offline extractor reads the dump, packet validation uses saved traffic without reference secrets, and the independent verifier reads the reference only after selection. The reference is therefore not an extraction input.

The scope remains Firefox 136.0.2/NSS, Linux x86-64, one controlled localhost TLS 1.2 ECDHE-RSA-AES128-GCM-SHA256 connection per fresh profile, captured while a response connection remains open. Approved disposable-session socket-sandbox and certificate-validation exceptions remain part of the conditions. GDB can omit unreadable regions. This is not evidence of breaking AES-GCM, testing weak CBC/RC4/3DES suites, recovering TLS 1.3 secrets, or generalizing to different browser versions, concurrent connections, capture timings or workloads.

## Retention and evidence

All campaign rows record deletion of the raw dump and disposable profile after results were saved; A's deletion is recorded in its separate repair record. The final runner reports 989,298,688 allocated bytes (about 943.5 MiB) across all pilot case directories, which also includes earlier development evidence. Small private PCAPs, candidate values, isolated references and verification logs remain on the host. Deleted campaign dumps cannot be rescanned later. Only non-secret manifests, summaries, JSON/CSV per-run records and the separate reanalysis summary are backed up here.

The lab service has completed and the periodic follow-up has been disabled. No new captures were started during the completion check.
