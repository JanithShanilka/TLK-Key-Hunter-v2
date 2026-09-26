(function () {
    "use strict";

    function findWolfSSLModule() {
        const modules = Process.enumerateModules();
        for (let i = 0; i < modules.length; i++) {
            if (modules[i].name.indexOf("libwolfssl") === 0) {
                return modules[i];
            }
        }
        return null;
    }

    const module = findWolfSSLModule();
    if (module === null) {
        console.log("[TLSKH_WORKLOAD] status=error reason=wolfssl_module_not_found");
        return;
    }

    const connectAddress = Module.findExportByName(module.name, "wolfSSL_connect");
    const writeAddress = Module.findExportByName(module.name, "wolfSSL_write");
    if (connectAddress === null || writeAddress === null) {
        console.log("[TLSKH_WORKLOAD] status=error reason=required_export_not_found");
        return;
    }

    const wolfSSLWrite = new NativeFunction(
        writeAddress,
        "int",
        ["pointer", "pointer", "int"]
    );
    const executable = Process.enumerateModules()[0].name;
    const protocol = executable.indexOf("_13_") !== -1 ? "TLS13" : "TLS12";
    const requestId = "REQUEST-" + Process.id;
    const nonce = Process.id.toString(16).toUpperCase();
    const requestPath =
        "/lab/BASELINE-WOLFSSL-" + protocol +
        "/RUN-01/" + requestId +
        "?nonce=" + nonce;
    const request =
        "GET " + requestPath + " HTTP/1.1\r\n" +
        "Host: localhost\r\n" +
        "Connection: close\r\n" +
        "User-Agent: TLSKeyHunter-Controlled-Baseline/1.0\r\n" +
        "\r\n";
    const requestBuffer = Memory.allocUtf8String(request);

    Interceptor.attach(connectAddress, {
        onEnter(args) {
            this.ssl = args[0];
        },

        onLeave(retval) {
            if (retval.toInt32() !== 1) {
                console.log("[TLSKH_WORKLOAD] status=skipped reason=tls_connect_failed");
                return;
            }

            const written = wolfSSLWrite(this.ssl, requestBuffer, request.length);
            console.log(
                "[TLSKH_WORKLOAD] status=request_sent" +
                " protocol=" + protocol +
                " request_id=" + requestId +
                " request_path=" + requestPath +
                " bytes=" + written
            );
        }
    });
})();
