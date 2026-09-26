(function () {
    "use strict";

    const root = typeof globalThis !== "undefined" ? globalThis : this;
    const library = String(root.TLSKH_LIBRARY || "").toLowerCase();
    const caseId = String(root.TLSKH_CASE_ID || "CASE-UNKNOWN");
    const protocol = String(root.TLSKH_PROTOCOL || "TLS-UNKNOWN");
    const runId = String(root.TLSKH_RUN_ID || "RUN-01");

    const api = library === "openssl"
        ? { connect: "SSL_connect", write: "SSL_write" }
        : library === "wolfssl"
            ? { connect: "wolfSSL_connect", write: "wolfSSL_write" }
            : null;

    if (api === null) {
        console.log("[TLSKH_WORKLOAD] status=error reason=unsupported_library");
        return;
    }

    function findExport(name) {
        const modules = Process.enumerateModules();
        for (let i = 0; i < modules.length; i++) {
            const address = Module.findExportByName(modules[i].name, name);
            if (address !== null) {
                return address;
            }
        }
        return null;
    }

    const connectAddress = findExport(api.connect);
    const writeAddress = findExport(api.write);
    if (connectAddress === null || writeAddress === null) {
        console.log(
            "[TLSKH_WORKLOAD] status=error reason=required_export_not_found" +
            " library=" + library
        );
        return;
    }

    const tlsWrite = new NativeFunction(
        writeAddress,
        "int",
        ["pointer", "pointer", "int"]
    );
    const requestId = "REQUEST-" + Process.id;
    const requestPath =
        "/lab/" + caseId + "/" + runId + "/" + requestId +
        "?protocol=" + protocol + "&library=" + library;
    const request =
        "GET " + requestPath + " HTTP/1.1\r\n" +
        "Host: localhost\r\n" +
        "Connection: close\r\n" +
        "User-Agent: TLSKeyHunter-Live-Forensics/1.0\r\n" +
        "\r\n";
    const requestBuffer = Memory.allocUtf8String(request);

    Interceptor.attach(connectAddress, {
        onEnter(args) {
            this.ssl = args[0];
        },

        onLeave(retval) {
            if (retval.toInt32() !== 1) {
                console.log(
                    "[TLSKH_WORKLOAD] status=skipped reason=tls_connect_failed" +
                    " library=" + library
                );
                return;
            }
            const written = tlsWrite(this.ssl, requestBuffer, request.length);
            console.log(
                "[TLSKH_WORKLOAD] status=request_sent" +
                " library=" + library +
                " protocol=" + protocol +
                " request_id=" + requestId +
                " request_path=" + requestPath +
                " bytes=" + written
            );
        }
    });

    console.log(
        "[TLSKH_WORKLOAD] status=ready library=" + library +
        " protocol=" + protocol
    );
})();
