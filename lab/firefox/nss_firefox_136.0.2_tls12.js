"use strict";

// Firefox 136.0.2 / NSS TLS 1.2 controlled-lab hook.
// The fingerprint and target binary are validated by the Python runner before
// this script is loaded.  This script intentionally emits no ClientHello
// random: the runner associates the 48-byte master-secret candidate with the
// single controlled ClientHello found in the case PCAP.

// The unique TLS_P_hash wrapper fingerprint anchors this hook to the frozen
// softoken build. The key result is read only after the matching NSS EMS-DH
// derivation API returns successfully.
const TLS12_PATTERN = "55 41 57 41 56 41 55 41 54 53 50 48 8B 05 96 F6 03 00 48 85 C0 74 17";
const TLS12_SECRET_LENGTH = 48;
const CKM_NSS_TLS_EXTENDED_MASTER_KEY_DERIVE_DH = 0xCE53436A;

function diagnostic(message) {
    send(String(message));
}

function readSecItem(item) {
    if (!item || item.isNull()) {
        return null;
    }
    try {
        const data = item.add(8).readPointer();
        const length = item.add(16).readU32();
        if (data.isNull() || length !== TLS12_SECRET_LENGTH) {
            return null;
        }
        const bytes = new Uint8Array(Memory.readByteArray(data, length));
        return Array.from(bytes)
            .map(function (value) { return value.toString(16).padStart(2, "0"); })
            .join("")
            .toUpperCase();
    } catch (error) {
        diagnostic("TLS 1.2 SECItem rejected: " + error.message);
        return null;
    }
}

function installDerivedKeyResultHook() {
    const deriveAddress = Module.findExportByName("libnss3.so", "PK11_DeriveWithFlags");
    const extractAddress = Module.findExportByName("libnss3.so", "PK11_ExtractKeyValue");
    const getDataAddress = Module.findExportByName("libnss3.so", "PK11_GetKeyData");
    if (deriveAddress === null || extractAddress === null || getDataAddress === null) {
        diagnostic("TLS 1.2 derived-key result API unavailable");
        return;
    }
    const extractKeyValue = new NativeFunction(extractAddress, "int", ["pointer"]);
    const getKeyData = new NativeFunction(getDataAddress, "pointer", ["pointer"]);
    Interceptor.attach(deriveAddress, {
        onEnter: function (args) {
            this.isTls12Master = false;
            try {
                this.isTls12Master = args[1].toUInt32() === CKM_NSS_TLS_EXTENDED_MASTER_KEY_DERIVE_DH;
            } catch (_) {}
        },
        onLeave: function (retval) {
            if (!this.isTls12Master || retval.isNull()) return;
            try {
                if (extractKeyValue(retval) !== 0) {
                    diagnostic("TLS 1.2 returned key could not be extracted");
                    return;
                }
                const item = getKeyData(retval);
                const secret = readSecItem(item);
                if (secret !== null) {
                    send("TLSKH_TLS12_SECRET extended master secret " + secret);
                } else {
                    diagnostic("TLS 1.2 returned key was not a 48-byte SECItem");
                }
            } catch (error) {
                diagnostic("TLS 1.2 returned-key read failed: " + error.message);
            }
        }
    });
    diagnostic("Attached TLS 1.2 post-return key-result hook");
}

function install() {
    const module = Process.findModuleByName("libsoftokn3.so");
    if (module === null) {
        setTimeout(install, 100);
        return;
    }
    installDerivedKeyResultHook();
    let matches = 0;
    Memory.scan(module.base, module.size, TLS12_PATTERN, {
        onMatch: function (address) {
            matches += 1;
            diagnostic("Pattern found at (tls12_p_hash): " + address);
        },
        onError: function (reason) {
            diagnostic("TLS 1.2 pattern scan failed: " + reason);
        },
        onComplete: function () {
            diagnostic("TLS 1.2 pattern scan complete matches=" + matches);
        }
    });
}

install();
