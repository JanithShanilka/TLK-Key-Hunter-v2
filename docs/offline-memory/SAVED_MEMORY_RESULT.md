# Firefox saved-memory pilot result

The controlled TLS 1.2 workflow succeeded on one development case and one subsequent fresh case with the method fixed in advance. This is a feasibility result, not a reliable population recovery percentage.

| Check | Development 008 | Fresh validation 009 |
|---|---:|---:|
| CKA_VALUE candidates from saved memory | 5 | 5 |
| Reference secret in candidate set | Yes | Yes |
| Memory-only ranking | Five tied first | Five tied first |
| Candidates passing saved-PCAP validation | 1 | 1 |
| Independently verified secret differences | 0 bits | 0 bits |
| Recovered-secret request and response decryption | Pass | Pass |
| One-bit wrong-secret control | Fails to decrypt | Fails to decrypt |

The extractor receives only saved Firefox process memory. A separate step resolves candidate ties using the saved PCAP and its public ClientHello random, without reading the reference key. After selection is sealed, an independent verifier compares it with the isolated server reference and verifies the controlled application markers. No Frida secret-export calls or Firefox key logging were used for acquisition.

For the held-out sample: candidate inclusion 1/1; unique memory-only selection 0/1 (abstention); packet-assisted exact recovery/decryption 1/1. Do not present this as an established 100% success rate. The rank score 75 is not a percentage of correct secret bits. TLS 1.3 has not been tested by this offline method; this does not demonstrate breaking TLS cryptography.

The tested environment is Firefox 136.0.2/NSS, Linux x86-64, localhost TLS 1.2 ECDHE-RSA-AES128-GCM-SHA256. Acquisition used the explicitly approved temporary socket-sandbox and certificate-validation exceptions. GDB reported unreadable regions; complete coverage of all mappings is not claimed. Setup attempts 001–007 remain recorded separately.

Two sparse cores are retained on the private lab host. Each appears around 9.2 GB, but all pilot case directories together occupy 940 MiB. Development reused the first dump; only one additional dump was captured for fresh validation. No raw memory was downloaded. A private HTML page containing lab secrets was later downloaded at the user’s request; it is excluded from Git. No secret files were uploaded to GitHub. Keep sparse allocation when archiving or copying.

See SAVED_MEMORY_WORK_LOG.md for chronology, frozen method hashes and limitations. Non-secret summaries are in summaries/FIREFOX-TLS12-CORE-PILOT-008/packet-assisted-summary.json and summaries/FIREFOX-TLS12-CORE-PILOT-009/packet-assisted-summary.json.
