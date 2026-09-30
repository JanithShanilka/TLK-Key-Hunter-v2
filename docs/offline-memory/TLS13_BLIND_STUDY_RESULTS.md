# Blind TLS 1.3 saved-memory study: final result

## Study boundary and provenance

This is a separate study from the historical [100-case extended validation](TLS13_EXTENDED_RESULTS.md). The historical code and results were preserved; those earlier cores were not available for a head-to-head comparison. The new recovery process received one saved Firefox memory image, its complete PCAP, and pinned target metadata. It received no message markers, server events, key logs, payload references, or supplied connection assignments.

The target was Firefox 136.0.2/NSS on Linux x86-64 with `TLS_AES_256_GCM_SHA384`. The controlled WebSocket workload used two or three overlapping connections and varied undisclosed payloads, with at least two application messages per direction before capture. Resumption, KeyUpdate, incomplete handshakes, other operating systems, and lifetime claims were excluded. A separate root-only evaluator held the answers. Both recovery outputs for each case were hashed and sealed before scoring.

The ten-case development pilot `BLIND-PILOT-20260930-C` completed before the final design was frozen. The final manifest was frozen as `BLIND-FINAL-20260930-A` with 100 neutral case IDs: 35 two-connection positives, 35 three-connection positives, and ten each of mismatched pairs, unrelated-traffic PCAPs, and withheld-secret derivatives. Acquisition starts were spaced by at least ten minutes. The final run finished at `2026-09-30T17:45:06Z`, with all 100 attempted cases scored and no processing failures. The [frozen manifest](campaigns/BLIND-FINAL-20260930-A/manifest.json) and [aggregate summary](campaigns/BLIND-FINAL-20260930-A/summary.json) are copied here without raw memory, traffic, or reference secrets.

## Results

| Outcome | Structured `CKA_VALUE` search | Entropy-filtered search |
| --- | ---: | ---: |
| Complete positive cases | **70/70** | 0/70 |
| Correct positive connection/direction targets | **350/350** | 1/350 |
| Controls meeting their declared outcome | **30/30** | 20/30 |
| False assignments across all cases | **0** | 0 |
| Reference secrets present in candidate sets, among 390 available targets | **390/390** | 1/390 |
| Median wall time per case | 23.0 s | 187.7 s |
| Median CPU time per case | 22.3 s | 186.9 s |
| Maximum observed peak RSS | 8.64 GiB | 8.22 GiB |

For the structured method, the controls comprised ten mismatched pairs with complete abstention, ten unrelated-traffic captures with complete abstention, and ten withheld-secret cases with partial recovery: 40 available directions recovered and the ten redacted directions unresolved. All had zero false assignments. The entropy method passed the 20 mismatched and unrelated controls through abstention, but recovered none of the required available directions in the withheld controls. Its one correct target was in a positive case and did not complete that case.

The predeclared paired difference in complete positive-case recovery was `1.0` in favor of the structured method. Its paired 95% bootstrap interval was `[1.0, 1.0]` across 20,000 resamples; every one of the 70 positive pairs favored the structured method. The declared strong-contribution rule was met: at least 63/70 complete positives, zero false assignments across 30 controls, a paired interval excluding zero, and no worse false-assignment rate.

## Comparison limits and retained evidence

Both searches used the same record-authentication and connection-assignment stage, a 180-second search budget, 300-second authentication budget, 100-candidate trial cap, 16-GiB virtual-memory limit, and 540-second CPU limit. Execution order alternated across cases, 50 first for each method. The structured search exhausted its candidate enumeration in all 100 cases; the entropy scan hit its time limit in all 100. The comparison therefore establishes an advantage over **this frozen entropy-only search under the equal resource budget**, not over every possible entropy-based method or longer scan.

The controlled generator, pinned Firefox/NSS build, and complete PCAPs limit generalization. The paired bootstrap interval describes these generated cases and does not establish performance across browser versions, operating systems, missing packets, or different TLS behavior. Zero observed false assignments is evidence for these 30 controls, not a guarantee of zero false assignments in other workloads.

The recovery account could not read the root-only evaluator references or case-type manifest, and the frozen recovery code reads only its declared core, PCAP, and metadata inputs. The run used Unix account and file permissions rather than a filesystem namespace exposing *only* those inputs. During a case, the second method could potentially inspect the first method's sealed output directory before the result parent was returned to root ownership. The frozen code does not do so, but this implementation does not establish the stricter operating-system isolation described in the original plan. A sandboxed replication should precede any claim that access to all other study files was technically impossible.

The host retained all 100 original memory images, ten redacted derivatives, 100 case PCAPs, ten decoy PCAPs, protected references, acquisition records and logs, and both methods' sealed outputs. A post-run audit verified all 200 seals, all 13 frozen script hashes, and an exact recomputation of the aggregate summary. The frozen manifest SHA-256 is `a75a7c2fda8ac17c7fba29523158a4ec74cd756a5016d172f686ce502ab57660`; the copied summary SHA-256 is `9ce3ca372b9a688b573f1da4bbf78d5f8178275181e10eaffa7b224469efe6c0`. Raw images, PCAPs, and secret logs remain private on the controlled host.
