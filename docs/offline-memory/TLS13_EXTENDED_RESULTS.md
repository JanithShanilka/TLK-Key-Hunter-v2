# TLS 1.3 extended saved-memory validation results

## Result

The five frozen repeat campaigns completed 100 of 100 controlled cases successfully. Each scenario contributed 20 cases with starts spaced by at least 600 seconds.

| Scenario | Recovery target | Attempted | Successful | Observed fraction |
| --- | --- | ---: | ---: | ---: |
| Before response | Generation-zero client and server traffic secrets while the response was gated | 20 | 20 | 1.00 |
| 30-second delay | Generation-zero client and server traffic secrets at least 30 monotonic seconds after the response | 20 | 20 | 1.00 |
| Resumption | Client and server generation-zero traffic secrets for the second, PSK-resumed connection | 20 | 20 | 1.00 |
| KeyUpdate | Client and server generation-one traffic secrets after a bidirectional KeyUpdate | 20 | 20 | 1.00 |
| Concurrency | Client and server generation-zero traffic secrets for each of two overlapping connections | 20 | 20 | 1.00 |
| **Total** |  | **100** | **100** | **1.00** |

The two-target scenarios validated 80 cases and the four-target concurrency scenario validated 20 cases. Candidate sets contained 9 to 20 values, with a median of 10. Case execution time ranged from 42.194 to 105.939 seconds, with a median of 50.541 seconds. These times exclude the required spacing between case starts.

## Acceptance evidence

All 100 repeat cases satisfied every recorded acceptance check:

- the scenario-specific condition passed before extraction;
- fixed-shape `CKA_VALUE` candidates were enumerated from saved memory without using the protected reference or packet contents;
- direct TLS 1.3 record authentication assigned exactly one candidate to every flow, direction, and target generation;
- the sealed selections equaled the root-only independent references exactly;
- every selected secret authenticated its exact controlled request or response marker;
- one-bit wrong-secret controls were rejected;
- cross-flow controls were rejected for concurrency, and generation-zero controls were rejected for KeyUpdate;
- KeyUpdate packet evidence authenticated both the server `update_requested` message and the client update response;
- raw core and disposable Firefox profile cleanup completed after durable result storage.

Every repeat campaign used the same recorded hashes for all ten acquisition, extraction, packet, and verification scripts. The nonsecret manifests, summaries, run records, and CSV exports are stored under `docs/offline-memory/campaigns/TLS13-EXT-*`.

## Pilot history

Each scenario passed a pilot before its repeat campaign became eligible. The before-response and delayed pilots passed on their first attempts. Resumption passed on pilot C after retaining failed pilot A and unsuccessful pilot B. KeyUpdate passed on pilot C after retaining unsuccessful pilots A and B. Concurrency passed on its first pilot. Those earlier attempts remain failures under the rules used when they ran and are not included in the 100 repeat cases.

The resumption recovery target is the second, completed resumed connection; the first full connection establishes the ticket and the condition. The KeyUpdate recovery target is post-update generation one; generation zero establishes and authenticates the update and serves as a wrong-generation control.

## Interpretation and limits

This result demonstrates repeatable recovery and independent authentication of TLS 1.3 application traffic secrets from saved Firefox process memory in this controlled localhost laboratory. It covers the fixed `TLS_AES_256_GCM_SHA384` cipher suite, the tested Firefox and host builds, the specified capture times, a completed PSK resumption, an explicitly driven bidirectional KeyUpdate, and two overlapping connections.

It does not establish a network-only attack or a general break of TLS 1.3. Acquisition required privileged access to save the browser process memory. Results may differ across browser versions, allocators, operating systems, cipher suites, process lifetimes, memory pressure, and connection state. The observed success fraction is descriptive of these 100 controlled cases and should not be treated as a universal recovery probability.

Secret values, ranked candidates, raw cores, disposable profiles, packet captures, and private logs remain on the controlled host and are not included in this repository. The committed records contain only nonsecret settings, script hashes, counts, booleans, timings, cleanup status, and evidence hashes.
