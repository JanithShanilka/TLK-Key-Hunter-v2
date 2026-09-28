# Saved-memory development pilot

Status: experimental. No successful offline Firefox secret recovery is claimed by the presence of these scripts.

This is separate from the published live Frida experiments. The first target is Firefox 136.0.2/NSS on the existing controlled Linux x86-64 host, using one localhost TLS 1.2 connection.

## Components

- `capture_firefox.py`: generates a disposable lab certificate/profile, starts a separate server reference process and packet capture, keeps a response connection open, identifies the Firefox process that owns the connection, and creates a private core dump. It never reads the server reference and does not load Frida or call an NSS secret-export API.
- `core_memory.py`: reads captured ELF64 x86-64 PT_LOAD bytes and rejects missing/truncated ranges. Captured virtual addresses are translated to file offsets.
- `rank_core.py`: experimental single-snapshot candidate ranking from SECItem-shaped objects (default) or PKCS#11 CKA_VALUE attributes (`--layout cka-value48`) with 48-byte readable buffers. It accepts no reference input. It deduplicates equal values, scores entropy/zero count and abstains when the highest score is tied. A structure shape is a heuristic, not proof of an NSS secret.
- `validate_candidates.py`: optionally tests sealed candidates against a saved single-connection PCAP, without a reference secret; selects only a unique candidate producing parsed HTTP request and response. This is packet-assisted selection and is reported separately from the memory ranker.
- `verify_core.py`: runs only after output sealing. It compares the independently selected candidate with the isolated reference, checks literal reference presence separately, and tests capture decryption. Reference-only sanity decryption is never counted as extraction success.

The single-snapshot method is not the original arg_ranker configuration D: it has no call argument list, before/after-call evidence or repeated-call history. Do not pool its results with the live experiments.

## Isolation and execution

Use the separate lab workspace `/home/researcher/research/TLSKeyHunter-memory-pilot`. Keep server references below `/root/tlkh-memory-reference` and run offline ranking as the unprivileged researcher. It should receive only the core file and a new output path. Privileged acquisition and verification operators can access the reference, so the experimental chronology and their commands must also be retained.

Example commands for a **new**, never-used case ID:

```sh
# Root: controlled capture. The script refuses to overwrite a case.
python3 tools/capture_firefox.py \
  --case "$PWD/cases/NEW-CASE-ID" \
  --reference /root/tlkh-memory-reference/NEW-CASE-ID

# Researcher: independently generate and seal candidates.
runuser -u researcher -- python3 tools/rank_core.py \
  --core "$PWD/cases/NEW-CASE-ID/firefox.core" \
  --output "$PWD/cases/NEW-CASE-ID/offline"

# Root: only after ranking has finished, verify with the reference.
python3 tools/verify_core.py \
  --case "$PWD/cases/NEW-CASE-ID" \
  --reference /root/tlkh-memory-reference/NEW-CASE-ID/server-reference.keys
```

Live capture briefly stops the target process. A successful GDB exit does not guarantee every memory mapping was captured; retain its warnings and mapping records. Core files, candidate lists and verification output may contain secrets and stay private on the lab host. Publish only reviewed summary JSON and non-secret logs.

The reference-guided presence audit answers whether literal reference bytes appear in captured mappings. It does not identify how they got there, establish blind recovery, or rule out transformed representations when no literal match is found. Final experimental success requires a candidate selected without the reference, exact equality, and recovery of both controlled application markers.

## Tests and records

```sh
python3 tests/test_offline_memory.py
```

Synthetic tests exercise address translation, omitted pages, truncated files, cross-segment search, candidate deduplication and abstention. They do not demonstrate Firefox recovery. The versioned experiment record is in [the work log](../../docs/offline-memory/SAVED_MEMORY_WORK_LOG.md), with [results](../../docs/offline-memory/SAVED_MEMORY_RESULT.md) and non-secret summary JSON alongside it.

## Storage and development evidence

Case 008 has a sparse core with 9,184,771,680 apparent bytes but about 281 MB allocated on the lab filesystem. Check both apparent size and allocated space before copying: ordinary transfers can expand sparse holes. Reuse this core for development and keep raw memory, candidate values and reference keys on the private lab host. Do not run a capture batch; review disk usage before a fresh validation case.

The initial SECItem scan produced 98 candidates and 68 top-score ties, selected none, and missed the reference value. Reference-guided auditing found the master secret once in captured bytes; reference-only decryption succeeded and a one-bit negative control failed. This demonstrates capture feasibility in this case, not extractor recovery. The CKA_VALUE alternative is a development hypothesis on this already-audited core.

Case 008 used the explicitly approved `--lab-disable-socket-sandbox` and `--lab-accept-insecure-certs` flags, both default off, within its disposable localhost session. The latter uses the installed lab Python environment with `websockets`; it does not validate certificate authentication. These conditions must accompany reported results.

## Packet-assisted TLS 1.2 workflow

For the experimental CKA_VALUE path, run ranking with `--layout cka-value48` and a new output directory, then:

```sh
runuser -u researcher -- python3 tools/validate_candidates.py \
  --offline "$PWD/cases/NEW-CASE-ID/offline-cka-v1" \
  --pcap "$PWD/cases/NEW-CASE-ID/traffic.pcap" \
  --output "$PWD/cases/NEW-CASE-ID/offline-cka-pcap-v1"

python3 tools/verify_core.py \
  --case "$PWD/cases/NEW-CASE-ID" \
  --reference /root/tlkh-memory-reference/NEW-CASE-ID/server-reference.keys \
  --offline-name offline-cka-pcap-v1 \
  --report-name verification-cka-pcap-v1
```

The ranker reads only saved memory. Packet validation additionally reads the saved PCAP and extracts its public ClientHello random. Only the final verifier reads the independent reference. Private temporary copies of the small PCAP/key inputs are automatically removed; cores are never copied by verification.

On development case 008, CKA_VALUE enumeration produced five tied candidates including the exact secret. Exactly one candidate passed packet validation. The subsequent independent check confirmed zero differing bits and decryption of both controlled markers; a one-bit-corrupted reference failed. This is development evidence, not a general recovery rate. Neither this pilot nor its 48-byte layout demonstrates TLS 1.3 recovery.

Fresh case 009 was acquired after fixing the method and also produced five tied memory candidates, exactly one packet-validation pass, an exact independent reference match, and successful controlled request/response decryption. This is one held-out success, not an established success-rate estimate. Unique memory-only selection remained unsuccessful (abstention). Two sparse cores are retained; all pilot case directories occupy 940 MiB.

`show_lab_evidence.py` generates a private HTML comparison from a completed, verified case. Its output contains actual lab secrets and is excluded by `*.private.*`; only the generator is versioned.

## Bounded repeatability campaign

`run_campaign.py` runs fresh localhost TLS 1.2 sessions sequentially. It snapshots and hashes the extraction scripts before starting, uses a new profile and case directory per attempt, preserves failures in the denominator, and records UTC times and stage logs. It never changes the extraction rules during the campaign. The runner requires root on the controlled lab host; ranking and packet validation still run as researcher without reference access.

The user-selected schedule is 20 sessions with a minimum ten-minute start-to-start interval. Every completed verification is saved before deleting that case's large raw core and disposable profile/runtime. Small PCAPs, sealed candidate lists, isolated references, acquisition metadata and verification outputs remain private for later analysis. Deleted dumps cannot be rescanned with a future extractor. A setup/tool failure stops the campaign and preserves its incomplete evidence for inspection; no automatic retry hides failed attempts.

```sh
python3 tools/run_campaign.py \
  --workspace /home/researcher/research/TLSKeyHunter-memory-pilot \
  --campaign-id TLS12-REPEAT-20260928-A \
  --count 20 --interval-seconds 600 \
  --budget-gib 8 --minimum-free-gib 20 \
  --lab-disable-socket-sandbox --lab-accept-insecure-certs
```

Run under the lab's service manager to survive SSH disconnects. The runner locks against another campaign, refuses an existing campaign ID, checks allocated storage during stages, and stops if the case budget or free-space guard is reached. These are operational guards, not a filesystem quota. No overlapping captures are scheduled. The approved compatibility flags remain explicit.

Under `campaigns/<campaign-id>/`, `manifest.json` records the frozen method and settings, `summary.json` records progress and storage, `runs.json`/`runs.csv` retain one row per attempted session, and individual result files preserve per-case results. Private evidence remains under `cases/` and `/root/tlkh-memory-reference/`. No bulk raw-data upload is part of the campaign. To stop gracefully after the current case, create an empty `STOP` file in the campaign directory. The runner will not resume a stopped campaign automatically.

Tests: `python3 tests/test_offline_campaign.py` checks failure accounting, storage decisions and stage failure handling. Existing memory-reader tests remain separate.

The first campaign attempt A-001 stopped because the frozen script directory lacked researcher traversal permission. Its original failure is preserved; subsequent analysis of the same dump succeeded and is recorded separately. Continuation B schedules the remaining 19 sessions, so there are 20 captures total across A and B. The runner now sets the snapshot directory mode explicitly after creation. See the versioned work log for provenance and retention outcomes.

The bounded campaign is complete. See [repeatability results](../../docs/offline-memory/REPEATABILITY_RESULTS.md) for all 20 attempts, the separate repair outcome, memory-ranking limitations and retained non-secret records.

The permanent finding is recorded in [Live-session secrets and offline recovery](../../docs/offline-memory/LIVE_SESSION_SECRETS_AND_OFFLINE_RECOVERY.md), including a redacted visual report. The [TLS 1.3 pilot plan](../../docs/offline-memory/TLS13_OFFLINE_PILOT_PLAN.md) is proposed work, not a completed recovery claim.
