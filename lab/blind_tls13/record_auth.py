"""Content-independent TLS 1.3 application-record authentication."""

from tls13_packets import decrypt_record, traffic_key_iv


def authenticate_application_epoch(records, secret, suite, minimum_records=2):
    """Find an application epoch beginning at sequence zero.

    A complete capture may contain encrypted handshake records before the
    application epoch. Once an epoch starts, every subsequent encrypted record
    must authenticate with consecutive sequence numbers. Plaintext records
    before the epoch are ignored; KeyUpdate is outside this study.
    """
    key, iv = traffic_key_iv(secret, suite)
    encrypted = [(index, record) for index, record in enumerate(records) if record[0] == 23]
    matches = []
    for start in range(len(encrypted)):
        application = []
        valid = True
        for sequence, (record_index, record) in enumerate(encrypted[start:]):
            opened = decrypt_record(record, key, iv, sequence)
            if opened is None or opened["inner_type"] not in (21, 22, 23):
                valid = False
                break
            if opened["inner_type"] == 23:
                application.append({"record_index": record_index, "sequence": sequence})
            # A KeyUpdate message would create another epoch and is excluded.
            if opened["inner_type"] == 22 and opened["content"].startswith(b"\x18\x00\x00\x01"):
                valid = False
                break
        if valid and len(application) >= minimum_records:
            matches.append({"first_record_index": encrypted[start][0],
                            "authenticated_records": len(encrypted) - start,
                            "application_records": application})
    return matches
