# TLS 1.3 repeatability campaign — completed

Twenty fresh Firefox TLS 1.3 sessions were captured ten minutes apart over about 3 hours 11 minutes. All 20 completed automatically. In every session, saved-traffic validation uniquely selected one client and one server application traffic secret from candidates extracted from saved Firefox memory. Independent post-selection verification confirmed exact matches and successful decryption in both directions.

| Measure | Observed result |
|---|---:|
| Attempted fresh sessions | 20 |
| Complete offline recovery | 20/20 (100% observed) |
| Exact client traffic-secret match | 20/20 |
| Exact server traffic-secret match | 20/20 |
| Request and response decrypted | 20/20 |
| Unique client packet-validation winner | 20/20 |
| Unique server packet-validation winner | 20/20 |
| Directional one-bit controls behaved as expected | 20/20 |
| Raw-core/profile cleanup recorded | 20/20 |

All sessions negotiated `TLS_AES_256_GCM_SHA384`. Each client and server application traffic secret therefore contained 384 bits. Every selected secret differed from its independent reference by zero bits. The extractor received no reference input; the reference was opened only after packet-assisted selection was sealed.

Candidate discovery returned nine candidates in four sessions and ten candidates in sixteen sessions, for 196 candidates across the campaign. Each session had exactly one candidate that decrypted the client request when assigned `CLIENT_TRAFFIC_SECRET_0`, and exactly one candidate that decrypted the server response when assigned `SERVER_TRAFFIC_SECRET_0`. Memory-only discovery did not assign directional roles; saved-PCAP validation remains part of the successful method.

The one-bit controls demonstrate directionality. Corrupting the selected client secret prevented request recovery while the correct server secret still recovered the response. Corrupting the server secret prevented response recovery while the correct client secret still recovered the request. Median end-to-end case time was 51.01 seconds; the mean was 54.84 seconds.

## Scope

These are observed results in the fixed lab environment: Firefox 136.0.2/NSS, Linux x86-64, one full localhost TLS 1.3 connection per fresh profile, `TLS_AES_256_GCM_SHA384`, no resumption, no 0-RTT and no intentional KeyUpdate. Approved disposable-session socket-sandbox and certificate-validation exceptions applied. The result does not establish universal TLS 1.3 recovery, SHA-256-suite behavior, concurrent-session behavior, different capture timing, browser versions, resumed sessions, 0-RTT, KeyUpdate, or memory-only role selection.

This does not break TLS 1.3 cryptography. It recovers endpoint-held traffic secrets from saved process memory and then uses the protocol's normal key-log interface to decrypt the matching saved traffic.

## Retention and evidence

The campaign began at 2026-09-28 11:15:00 UTC and ended at 14:26:03 UTC (16:45:00 to 19:56:03 Asia/Colombo). Each raw core and disposable profile/runtime was deleted only after durable verification results were saved. All 20 cleanup records are present. Final allocated storage across all retained pilot case directories was 995,569,664 bytes; that total also includes earlier compact evidence.

Only the non-secret [manifest](campaigns/TLS13-REPEAT-20260928-A/manifest.json), [summary](campaigns/TLS13-REPEAT-20260928-A/summary.json), [JSON rows](campaigns/TLS13-REPEAT-20260928-A/runs.json), and [CSV rows](campaigns/TLS13-REPEAT-20260928-A/runs.csv) are versioned. Actual traffic secrets, PCAPs and private candidate files remain outside Git.
