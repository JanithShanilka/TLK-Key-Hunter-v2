/*
Invoke

frida -p $(frida-ps | grep -i test_client | awk '{print $1}') -l arg_ranker.js -l openssl_key_dump_linux_x86_64.js

*/

// Constants for parsing
const SSL3_RANDOM_SIZE = 32; // Assuming SSL3_RANDOM_SIZE is 32 bytes
const SSL_MAX_MD_SIZE = 48;  // Assuming SSL_MAX_MD_SIZE is 64 bytes
const TLS12_MASTER_SECRET_LENGTH = 48;
const TLS13_SECRET_LENGTH = 48; // Frozen TLS_AES_256_GCM_SHA384 baseline.

const __tlskhConsoleLog = console.log.bind(console);
const __tlskhConsoleError = console.error ? console.error.bind(console) : __tlskhConsoleLog;

function formatLogArgs(args) {
    return Array.prototype.slice.call(args).map(function (arg) {
        try {
            return String(arg);
        } catch (e) {
            return "<unprintable>";
        }
    }).join(" ");
}

console.log = function () {
    __tlskhConsoleLog("[DEBUG] " + formatLogArgs(arguments));
};

console.warn = function () {
    __tlskhConsoleLog("[WARN] " + formatLogArgs(arguments));
};

console.error = function () {
    __tlskhConsoleError("[ERROR] " + formatLogArgs(arguments));
};

function rankerLog() {
    __tlskhConsoleLog("[RANKER] " + formatLogArgs(arguments));
}

function writeKeyLogLine(label, clientRandom, secret) {
    const validLabels = {
        "CLIENT_RANDOM": true,
        "CLIENT_HANDSHAKE_TRAFFIC_SECRET": true,
        "SERVER_HANDSHAKE_TRAFFIC_SECRET": true,
        "CLIENT_TRAFFIC_SECRET_0": true,
        "SERVER_TRAFFIC_SECRET_0": true
    };

    if (!validLabels[label]) {
        console.warn("Skipping unsupported key-log label:", label);
        return false;
    }
    if (!clientRandom || !secret) {
        console.warn("Skipping incomplete key-log line for label:", label);
        return false;
    }

    __tlskhConsoleLog(label + " " + clientRandom + " " + secret);
    return true;
}

// Dynamic offsets based on architecture
const is64Bit = Process.arch === 'x64';

const boringSSL_Handshake_struct = is64Bit
    ?  { 
    secret: 0x48, 
    earlyTrafficSecret: 0x96, 
    clientHandshakeSecret: 0x144, 
    serverHandshakeSecret: 0x192, 
    clientTrafficSecret0: 0x240, 
    serverTrafficSecret0: 0x288, 
    expectedClientFinished: 0x336, 
    innerClientRandom: 0x384, 
    } 
    : { 
    secret: 0x150, 
    earlyTrafficSecret: 0x180, 
    clientHandshakeSecret: 0x1B0,
    erverHandshakeSecret: 0x1E0, 
    clientTrafficSecret0: 0x210, 
    serverTrafficSecret0: 0x240, 
    expectedClientFinished: 0x270, 
    innerClientRandom: 0x2A0, 
    };




// some global definitions
var did_check = false;
var session_client_random = "";

function captureArgs(args, maxArgs) {
    var captured = [];
    for (var i = 0; i < maxArgs; i++) {
        try {
            captured[i] = args[i];
        } catch (e) {
            captured[i] = null;
        }
    }
    return captured;
}

function captureBeforeHexByIndex(argsSnapshot, expectedLength, excludeIndexes) {
    var before = {};
    var excluded = excludeIndexes || [];
    for (var i = 0; i < argsSnapshot.length; i++) {
        if (excluded.indexOf(i) !== -1) {
            continue;
        }
        var data = safeReadByteArray(argsSnapshot[i], expectedLength);
        if (data !== null) {
            before[i] = byteArrayToHex(data);
        }
    }
    return before;
}

function pointerLooksSane(pointerValue) {
    try {
        if (pointerValue === null || pointerValue === undefined || pointerValue.isNull()) {
            return false;
        }
        var value = pointerValue.toString().replace(/^0x/i, "").replace(/^0+/, "");
        return value.length > 3;
    } catch (e) {
        return false;
    }
}

function safeReadByteArray(pointerValue, size) {
    try {
        if (!pointerLooksSane(pointerValue)) {
            return null;
        }
        Memory.readU8(pointerValue);
        return Memory.readByteArray(pointerValue, size);
    } catch (e) {
        console.warn("Memory read failed at", pointerValue, "size", size, e.message);
        return null;
    }
}

function safeReadCString(pointerValue, maxLength) {
    try {
        if (!pointerLooksSane(pointerValue)) {
            return null;
        }
        Memory.readU8(pointerValue);
        return pointerValue.readCString(maxLength || 64);
    } catch (e) {
        console.warn("CString read failed at", pointerValue, e.message);
        return null;
    }
}

function makeFallbackCandidate(args, index, reason) {
    var pointerValue = null;
    try {
        pointerValue = args[index];
    } catch (e) {
        pointerValue = null;
    }
    return {
        index: index,
        pointer: pointerValue,
        score: 1,
        reasons: [reason || "fallback_hardcoded"]
    };
}

function getArgRanker() {
    var root = typeof globalThis !== "undefined" ? globalThis : this;
    if (typeof root.ArgRanker !== "undefined") {
        return root.ArgRanker;
    }

    return {
        rankSecretCandidates: function (args, expectedLengths, context) {
            return [];
        },
        rankLabelCandidates: function (args, context) {
            return [];
        },
        rankClientRandomCandidates: function (args, expectedLengths, context) {
            return [];
        },
        rankIntegerCandidates: function (args, context) {
            return [];
        },
        rankStructureCandidates: function (args, context) {
            return [];
        },
        selectUniqueCandidate: function () {
            return { status: "no_candidate", candidate: null, tiedIndexes: [] };
        },
        bytesToHex: byteArrayToHex
    };
}

function rankerMode() {
    var root = typeof globalThis !== "undefined" ? globalThis : this;
    return root.TLSKH_RANKER_MODE === "A" ? "A" : "D";
}

function selectSecretCandidate(candidates, args, fallbackIndex, kind) {
    if (rankerMode() === "A") {
        var hardcoded = makeFallbackCandidate(args, fallbackIndex, "original_hardcoded");
        rankerLog(
            kind + " args[" + fallbackIndex + "]",
            "mode=A",
            "score=hardcoded",
            "reasons=original_hardcoded"
        );
        return hardcoded;
    }

    var decision = getArgRanker().selectUniqueCandidate(candidates || []);
    if (decision.status !== "selected") {
        rankerLog(
            kind,
            "mode=D",
            "status=" + decision.status,
            "tied=" + decision.tiedIndexes.join(",")
        );
        return null;
    }
    var selected = decision.candidate;
    rankerLog(
        kind + " args[" + selected.index + "]",
        "mode=D",
        "score=" + selected.score,
        "reasons=" + selected.reasons.join(",")
    );
    return selected;
}

function selectCandidate(candidates, args, fallbackIndex, kind) {
    var selected = candidates && candidates.length > 0 ? candidates[0] : null;
    if (!selected || selected.pointer === null || selected.pointer === undefined) {
        rankerLog(kind, "no_candidate", "fallback_disabled", "former_args[" + fallbackIndex + "]");
        return null;
    }

    rankerLog(
        kind + " args[" + selected.index + "]",
        "score=" + selected.score,
        "reasons=" + selected.reasons.join(","),
        "ptr=" + selected.pointer
    );
    return selected;
}

function candidateHex(candidate, length) {
    if (candidate && candidate.hex) {
        return candidate.hex;
    }

    var data = safeReadByteArray(candidate ? candidate.pointer : null, length);
    return byteArrayToHex(data);
}

/*

Usually we can expect after the label are length value of that label.
The PRF would have a length of 0xD (13) and the HKDF 0xC (12)


*/

function get_working_func_args(context, check_for_length, is_hkdf){
     // Initialize an empty array to store arguments
     var argument_array = [];
     console.log("[*] Hooked function onEnter!");

     try {
         for (var i = 0; ; i++) { // Iterate until we hit an exception
            if(i > 12){
                return argument_array;
            }
             try {
                 var arg = context[i]; // // Access the ith argument
                 if (arg) {
                     argument_array.push(arg); // Save argument for later use
                     console.log('[*] Argument ' + i + ' at address ' + arg + ':');

                     if(check_for_length){
                        if(is_hkdf && arg == 0xC){
                            console.log("[*] Found probably label length value...");
                            //return argument_array;
                        }else if(!is_hkdf && arg == 0xD){
                            return argument_array;
                        }

                     }

                 } else {
                     console.log('[*] Argument ' + i + ' is null.');
                     argument_array.push(null);
                 }
             } catch (e) {
                 console.log('[!] Reached end of arguments at index ' + i + '.');
                 console.log(e.message);
                 return argument_array; // Exit the loop when we can't access more arguments
             }
         }
     } catch (e) {
         console.log('[!] Error in onEnter: ' + e.message);
         return argument_array;
     }
}



// Function to parse the SSL_HANDSHAKE structure of OpenSSL
// More infos at https://github.com/google/boringssl/blob/d9ad235cd8c203db7430c366751f1dddcf450060/ssl/internal.h#L1899
function parseSSLHandshake(structPointer) {
    try {
        var abi = is64Bit ? "x86-64" : "x86";
        console.log("Parsing SSL_HANDSHAKE on "+abi);
        // Pointer to the structure
        const sslHandshake = ptr(structPointer);
        console.log("[*] Parsing SSL_HANDSHAKE at address:", sslHandshake);

        // Access `inner_client_random`
        const innerClientRandom = Memory.readByteArray(
            sslHandshake.add(boringSSL_Handshake_struct.innerClientRandom),
            SSL3_RANDOM_SIZE
        );
        console.log("[*] inner_client_random:", byteArrayToHex(innerClientRandom));

        // Access keys
        const keys = {};
        for (const [key, offset] of Object.entries(boringSSL_Handshake_struct)) {
            if (key !== "innerClientRandom") {
                const keyData = Memory.readByteArray(
                    sslHandshake.add(offset),
                    SSL_MAX_MD_SIZE
                );
                keys[key] = byteArrayToHex(keyData);
            }
        }

        // Print all keys
        for (const [key, value] of Object.entries(keys)) {
            console.log(`[*] ${key}:`, value);
        }
    } catch (error) {
        console.error("[!] Error parsing SSL_HANDSHAKE:", error.message);
    }
}

// Utility function to convert byte array to hex
function byteArrayToHex(byteArray) {
    if (!byteArray) return null;
    const array = new Uint8Array(byteArray);
    return Array.from(array)
        .map(byte => byte.toString(16).padStart(2, "0"))
        .join("");
}

function isMemoryReadable(ptr, size) {
    try {
        if (!pointerLooksSane(ptr)) {
            console.warn("Skipping invalid or null pointer:", ptr);
            return false;
        }

        Memory.readU8(ptr);
        if (size && size > 1) {
            Memory.readByteArray(ptr, size);
        }
        return true;
    } catch (e) {
        console.warn("Memory not readable at", ptr, e.message);
        return false;
    }
}



function isAsciiString(bytes) {
    try {
        var view = new Uint8Array(bytes); // Convert to a byte array for iteration
        var asciiString = "";

        for (var i = 0; i < view.length; i++) {
            var byte = view[i];

            // Check if byte is printable ASCII or null-terminator
            if ((byte >= 0x20 && byte <= 0x7E) || byte === 0) {
                if (byte === 0) {
                    // Null-terminator found, stop here
                    break;
                }
                asciiString += String.fromCharCode(byte);
            } else {
                // Non-printable character found
                return false;
            }
        }

        return asciiString.length > 0 ? true : false; // Return the string if valid
    } catch (e) {
        console.log("[!] Error while validating string:", e.message);
        return false;
    }
}


function check_arguments(memoryPointer, arg_number){
    console.log("[*] Argument points to:", memoryPointer);


    // Try to read the memory region
    try {
        console.log("[*] Dumping memory at address:", memoryPointer);
        var memoryContent = dumpMemory(memoryPointer, 0x40);
        if(memoryContent != null){
            var is_arg_a_string = isAsciiString(memoryContent);
            if(is_arg_a_string){
                console.log("[+] Label found at argument ", arg_number);
            }else{
                try{
                    console.log("[!] Not a string: ",e.message); // actually a weird bug, when I don't have this exception the target program keeps crashing 
                }catch(e) {
                    console.log("[*] Not a String. Start to check its entropy...");

                    var num_zero_bytes = countZeroBytes(memoryContent);
                    if(num_zero_bytes > 5){
                        console.log("[*] Too many zero bytes. Unlikely a cryptographic key at argument "+arg_number);
                    }else{
                        console.log("[*] Likely a cryptographic key at argument "+arg_number);
                    }

                    /*
                
                    // check entropy
                    var entropy = calculateEntropy(memoryContent);
                    console.log("[*] Entropy:", entropy);

                    if (entropy > 4.0) {
                        console.log("[+] High entropy detected. Likely a cryptographic key at argument "+arg_number);
                    } else {
                        console.log("[+] Low entropy. Unlikely to be a key.");
                    } */

                }
                

            }

        }else{
            console.log("[!] Memory is not accessible.");
            console.log("[!] Argument "+arg_number+" is not a valid for a label or a key...");
        }

    } catch (e) {
        console.log("[!] Error accessing memory:", e.message);
        console.log("[!] Argument "+arg_number+" is not a valid argument...");
    }

}

function countZeroBytes(memoryContent) {
    // Ensure the content is valid
    if (!memoryContent || memoryContent.byteLength === 0) {
        console.log("[!] No memory content to analyze.");
        return 0;
    }

    // Convert the memory content into a typed array (Uint8Array)
    var byteArray = new Uint8Array(memoryContent);

    // Count the number of zero bytes
    var zeroCount = 0;
    // 32 is the number of bytes a TLS key usually has
    for (var i = 0; i < 32; i++) {
        if (byteArray[i] === 0x00) {
            zeroCount++;
        }
    }

    console.log(`[+] Found ${zeroCount} zero bytes in the memory region.`);
    return zeroCount;
}

// Function to calculate Shannon entropy
function calculateEntropy(byteArray) {
    const keyLength = 48;
    const frequency = new Array(256).fill(0); // Array for byte frequency (0-255)
    const length = Math.min(byteArray.byteLength, keyLength); // Limit to key length

    // Count byte occurrences
    const bytes = new Uint8Array(byteArray.slice(0,length));
    for (let i = 0; i < length; i++) {
        frequency[bytes[i]]++;
    }

    // Calculate entropy
    let entropy = 0;
    const epsilon = 1e-10; // Avoid issues with very small probabilities
    for (let i = 0; i < 256; i++) {
        if (frequency[i] > 0) {
            // Calculate the probability of this byte value
            const p = frequency[i] / length;
            entropy += p.toFixed(2);
            //const roundedP = p.toFixed(4); // Ensure a fixed precision parseFloat(p.toFixed(6));
            //let tmp = Math.log2(roundedP);
            
            /*if (roundedP > epsilon) { // Avoid extremely small probabilities
                //entropy -= roundedP * Math.log2(roundedP); // Use the rounded value
            }*/
        }
    }

    return entropy;
}


function dumpMemory(ptrValue,size) {
    //var size = 0x100;
    try {
        var data = Memory.readByteArray(ptrValue, size);
        console.log(hexdump(data));
        return data;
        // console.log(hexdump(data, { offset: 0, length: size, header: true, ansi: true }));
    } catch (error) {
        console.log("Error dumping memory at: " + ptrValue + " - " + error.message);
        console.log("\n")
        return null;
    }
}


// Function to dynamically handle arguments and dump them
function dumpFunctionArguments(context, maxArgs) {
    //console.log("Context content:"+JSON.stringify(context));
    for (var i = 0; i < maxArgs; i++) {
        try {
            var arg = context[i]; // Access the ith argument
            if (arg) {
                console.log('Argument ' + i + ' at address ' + arg + ':');
                dumpMemory(arg, 0x80); // Dump the first 32 bytes of the memory (adjust as needed)
                //var memoryContent = Memory.readByteArray(arg, 48); // Read 48 bytes - default key size
                //var entropy = calculateEntropy(memoryContent);
                //console.log("[*] Entropy:", entropy);
                //check_arguments(arg, i); // check for entropy and if there is a pointer to a string
            } else {
                console.log('Argument ' + i + ' is null or invalid.');
            }
        } catch (e) {
            console.log('Could not access argument ' + i + ': ' + e.message);
        }
    }
}

const tlsLabelMapping = {
    // TLS 1.3 Secrets
    "c ap traffic": "CLIENT_TRAFFIC_SECRET_0",
    "s ap traffic": "SERVER_TRAFFIC_SECRET_0",
    "c hs traffic": "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
    "s hs traffic": "SERVER_HANDSHAKE_TRAFFIC_SECRET",
    "e traffic": "EARLY_TRAFFIC_SECRET",
    "c finished": "CLIENT_FINISHED",
    "s finished": "SERVER_FINISHED",
    //"res master": "RESUMPTION_MASTER_SECRET",
    
    // TLS 1.2 Secrets
    "master secret": "MASTER_SECRET",
    "extended master secret": "MASTER_SECRET",
    "exp master": "EXPORTER_SECRET",
    "c finished tls12": "CLIENT_FINISHED_TLS12",
    "s finished tls12": "SERVER_FINISHED_TLS12",
    "c key expansion": "CLIENT_KEY_EXPANSION",
    "s key expansion": "SERVER_KEY_EXPANSION",
    "c ap key tls12": "CLIENT_APPLICATION_TRAFFIC_KEY_TLS12",
    "s ap key tls12": "SERVER_APPLICATION_TRAFFIC_KEY_TLS12",
    
    // Additional TLS 1.3 Labels
    "key update requested": "KEY_UPDATE_REQUESTED",
    "key update not requested": "KEY_UPDATE_NOT_REQUESTED",
    
    // Additional TLS 1.2 Labels
    "client write mac key": "CLIENT_WRITE_MAC_KEY",
    "server write mac key": "SERVER_WRITE_MAC_KEY",
    "client write key": "CLIENT_WRITE_KEY",
    "server write key": "SERVER_WRITE_KEY",
    "client iv": "CLIENT_IV",
    "server iv": "SERVER_IV",
    "key expansion": "CLIENT_RANDOM",
    
    // General Labels
    "c key": "CLIENT_KEY",
    "s key": "SERVER_KEY",
};




function get_key_from_ptr(key_ptr){
    const KEY_LENGTH = 32; // Assuming 32 bytes for this example, change this as required.
    if (pointerLooksSane(key_ptr)) {
        const keyData = safeReadByteArray(key_ptr, KEY_LENGTH);
        if (keyData === null) {
            return "";
        }
        
        // Convert the byte array to a string of space-separated hex values
        const hexKey = Array
            .from(new Uint8Array(keyData)) // Convert byte array to Uint8Array and then to Array
            .map(byte => byte.toString(16).padStart(2, '0').toUpperCase()) // Convert each byte to a 2-digit hex string
            .join(''); // Join all the hex values with a space


        console.log("Key: "+hexKey); // Print the key as a space-separated hex string
    }

}


function get_label(label_to_span){
    var labelStr = "";
    try{
        if (pointerLooksSane(label_to_span)) {
            var label = safeReadCString(label_to_span, 64);
            if (label === null) {
                return "";
            }
            labelStr = getTLSLabel(label);
            if(labelStr === null){
                return "";
            }else{
                //console.log("Get Label result: "+labelStr);
                return labelStr;
            }
        }
    }catch(error){
        console.error("Error reading pointer from label_to_span:", error.message);
        return "";
    }
}


function is_arg_key_exp(ptr){
    var labelStr = "";
    try{
        if (pointerLooksSane(ptr)) {
            var label = safeReadCString(ptr, 64);
            if (label === null) {
                return false;
            }
            labelStr = label;
            if(labelStr === null){
                return false;
            }else{
                if(labelStr === "key expansion"){
                    return true;
                }
                return false;
            }
        }
    }catch(error){
        console.error("Error reading pointer from label_to_span:", error.message);
        return false;
    }
}



function getTLSLabel(input) {
    let label = tlsLabelMapping[input.toLowerCase()];
    if (label) {
        //console.log("Found TLS label: " + label);
        return label;
    } else {
        //console.log("TLS label not found for input: " + input);
        return null;
    }
}

function get_client_random(s3_ptr,SSL3_RANDOM_SIZE) {
    // Check if s3 pointer is valid
    if (pointerLooksSane(s3_ptr)) {
        // Offset for client_random is 0x30 in the s3 struct
        var client_random_ptr = s3_ptr.add(0x30);

        // Read the client_random bytes (32 bytes)
        var client_random = safeReadByteArray(client_random_ptr, SSL3_RANDOM_SIZE);
        if (client_random === null) {
            return "";
        }

        // Convert the bytes to an uppercase, concatenated hex string
        const hexClientRandom = Array
            .from(new Uint8Array(client_random))
            .map(byte => byte.toString(16).padStart(2, '0').toUpperCase()) // Convert to uppercase hex
            .join(''); // Concatenate the hex values without spaces

        //console.log("client_random (32 bytes): " + hexClientRandom);
        return hexClientRandom;
    } else {
        console.warn("s3 pointer is NULL or invalid");
    }
}

function get_client_random_from_ssl_struct(ssl_st_ptr){
    // parses the ssl_st in order to get the client_random
    // Define the size of SSL3_RANDOM_SIZE (usually 32 bytes)
    const SSL3_RANDOM_SIZE = 32;


    /* 
    https://github.com/google/boringssl/blob/d9ad235cd8c203db7430c366751f1dddcf450060/ssl/internal.h#L3926C1-L3958C53

    struct ssl_st {
      explicit ssl_st(SSL_CTX *ctx_arg);
      ssl_st(const ssl_st &) = delete;
      ssl_st &operator=(const ssl_st &) = delete;
      ~ssl_st();

      // method is the method table corresponding to the current protocol (DTLS or
      // TLS).
      const bssl::SSL_PROTOCOL_METHOD *method = nullptr;

      // config is a container for handshake configuration.  Accesses to this field
      // should check for nullptr, since configuration may be shed after the
      // handshake completes.  (If you have the |SSL_HANDSHAKE| object at hand, use
      // that instead, and skip the null check.)
      bssl::UniquePtr<bssl::SSL_CONFIG> config;

      // version is the protocol version.
      uint16_t version = 0;

      uint16_t max_send_fragment = 0;

      // There are 2 BIO's even though they are normally both the same. This is so
      // data can be read and written to different handlers

      bssl::UniquePtr<BIO> rbio;  // used by SSL_read
      bssl::UniquePtr<BIO> wbio;  // used by SSL_write

      // do_handshake runs the handshake. On completion, it returns |ssl_hs_ok|.
      // Otherwise, it returns a value corresponding to what operation is needed to
      // progress.
      bssl::ssl_hs_wait_t (*do_handshake)(bssl::SSL_HANDSHAKE *hs) = nullptr;

      bssl::SSL3_STATE *s3 = nullptr;   // TLS variables



    https://github.com/google/boringssl/blob/d9ad235cd8c203db7430c366751f1dddcf450060/ssl/internal.h#L2793C1-L2803C49



    struct SSL3_STATE {
          static constexpr bool kAllowUniquePtr = true;

          SSL3_STATE();
          ~SSL3_STATE();

          uint64_t read_sequence = 0;
          uint64_t write_sequence = 0;

          uint8_t server_random[SSL3_RANDOM_SIZE] = {0};
          uint8_t client_random[SSL3_RANDOM_SIZE] = {0};
    */
    var arch = Process.arch;
    var offset_s3 = 0x30;

    if (arch === 'x64' || arch === 'arm64') {
        offset_s3 = 0x30;  // Offset for x86-64 and arm64
    } else if (arch === 'x86' || arch === 'arm') {
        offset_s3 = 0x2C;  // Offset for x86 and arm
    }
    


    if (!pointerLooksSane(ssl_st_ptr)) {
        console.warn("ssl_st pointer is NULL or invalid");
        return "";
    }

    try {
        Memory.readU8(ssl_st_ptr.add(offset_s3));
        var s3_ptr = ssl_st_ptr.add(offset_s3).readPointer();
        return get_client_random(s3_ptr,SSL3_RANDOM_SIZE);
    } catch (e) {
        console.warn("Unable to read s3 pointer from ssl_st:", e.message);
        return "";
    }
}


function get_ssl_ptr_from_handshake(hs_ptr) {
    try {
        if (!pointerLooksSane(hs_ptr)) {
            return ptr(0);
        }
        var hs = hs_ptr;  // SSL_HANDSHAKE *hs is passed as the first argument
        Memory.readU8(hs.add(0x8));
        return hs.add(0x8).readPointer();  // Since SSL *ssl is at offset 0
    } catch (e) {
        console.warn("Unable to read SSL pointer from handshake:", e.message);
        return ptr(0);
    }
}

function dump_keys(label, identifier,key) {
    // Set the expected length of the key (in bytes). Adjust as needed.
    const KEY_LENGTH = 32; // Assuming 32 bytes for this example, change this as required.
    var labelStr = "";
    var client_random = "";
    var secret_key = "";

    // Read and print the string from label (first parameter)
    //console.log("Label:");
    if (pointerLooksSane(label)) {
        labelStr = safeReadCString(label, 64);
        //console.log("Label: "+labelStr);
    } else {
        console.warn("Argument 'label' is NULL or invalid");
    }

    if (pointerLooksSane(identifier)) {
        console.log("SSL_Struct_pointer (working): ",identifier);
        client_random = get_client_random_from_ssl_struct(identifier)
    } else {
        console.warn("Argument 'identifier' is NULL or invalid");
    }


    // Read the binary key from key (second parameter) and print it in a clean hex format
    //console.log("Key:");
    if (pointerLooksSane(key)) {
        const keyData = safeReadByteArray(key, KEY_LENGTH);
        if (keyData === null) {
            return false;
        }
        
        // Convert the byte array to a string of space-separated hex values
        const hexKey = Array
            .from(new Uint8Array(keyData)) // Convert byte array to Uint8Array and then to Array
            .map(byte => byte.toString(16).padStart(2, '0').toUpperCase()) // Convert each byte to a 2-digit hex string
            .join(''); // Join all the hex values with a space

        secret_key = hexKey;

        //console.log("Key: "+hexKey); // Print the key as a space-separated hex string
    } else {
        console.warn("Argument 'key' is NULL or invalid");
        return false;
    }

    writeKeyLogLine(labelStr, client_random, secret_key);
    return true;
}

/*
"CLIENT_TRAFFIC_SECRET_0"
"c ap traffic" */

function dump_keys_from_derive_secrets(client_random, key, label_to_span, key_length) {
    
    const KEY_LENGTH = key_length || TLS13_SECRET_LENGTH;
    var labelStr = "";
    var secret_key = "";

    if (pointerLooksSane(label_to_span)) {
        var label = safeReadCString(label_to_span, 64);
        if (label === null) {
            return false;
        }
        labelStr = getTLSLabel(label);
        if(labelStr === null){
            return false;
        }
    } else {
        console.warn("Argument 'label' is NULL or invalid");
        return false;
    }

    if (pointerLooksSane(key)) {
        const keyData = safeReadByteArray(key, KEY_LENGTH);
        if (keyData === null) {
            return false;
        }
        
        const hexKey = Array
            .from(new Uint8Array(keyData))
            .map(byte => byte.toString(16).padStart(2, '0').toUpperCase())
            .join('');

        secret_key = hexKey;
    } else {
        console.warn("Argument 'key' is NULL or invalid");
        return false;
    }

    console.log("[TLSKH_CANDIDATE] " + labelStr + " " + secret_key);
    return true;
}


function dump_keys_from_prf(client_random_ptr, key, key_length) {
    
    const KEY_LENGTH = key_length || TLS12_MASTER_SECRET_LENGTH;
    var labelStr = "CLIENT_RANDOM";
    var client_random = "";
    var secret_key = "";


    if (pointerLooksSane(key)) {
        const keyData = safeReadByteArray(key, KEY_LENGTH);
        if (keyData === null) {
            return false;
        }
        
        const hexKey = Array
            .from(new Uint8Array(keyData))
            .map(byte => byte.toString(16).padStart(2, '0').toUpperCase())
            .join('');

        secret_key = hexKey;
    } else {
        console.warn("Argument 'key' is NULL or invalid");
        return false;
    }

    if(pointerLooksSane(client_random_ptr)){
        var RANDOM_KEY_LENGTH = 32;
        const keyData = safeReadByteArray(client_random_ptr, RANDOM_KEY_LENGTH);
        if (keyData === null) {
            return false;
        }
        
        const hexClient_random = Array
            .from(new Uint8Array(keyData))
            .map(byte => byte.toString(16).padStart(2, '0').toUpperCase())
            .join('');

            client_random = hexClient_random;

    }else {
        console.warn("Argument 'client_random_ptr' is NULL or invalid");
        return false;
    }

    writeKeyLogLine(labelStr, client_random, secret_key);
    return true;
}


function get_client_random_from_ssl_connection(clabel, ssl_connection){
    if (pointerLooksSane(clabel) && pointerLooksSane(ssl_connection)) {
        var label = safeReadCString(clabel, 64);
        if (label === null) {
            return "";
        }
        var labelStr = getTLSLabel(label);
        if (labelStr && labelStr.includes("HANDSHAKE_TRAFFIC")) {
            // Read client_random from ssl_connection (args[0]) with an offset of 148
            var clientRandomPtr = ssl_connection.add(0x148);
            var clientRandomData = safeReadByteArray(clientRandomPtr, 32);
            if (clientRandomData !== null) {
                var client_random = Array
                    .from(new Uint8Array(clientRandomData))
                    .map(byte => byte.toString(16).padStart(2, '0').toUpperCase())
                    .join('');
                return client_random;
            }
        }
    }
    return ""; // couldn't get client_random
}


function hookOpenSSLByPattern(module) {
    var moduleBase = module.base;
    var moduleSize = module.size;

    console.log("Module Base Address: " + moduleBase);
    console.log("Module Size: " + moduleSize);

    // First pattern to try
    var arch = Process.arch;
    console.log("[*] Start hooking on arch: "+arch)


    // hooking this result into a suspending state of openssl client
    var pattern_mb_derive_secret = "F3 0F 1E FA 55 49 89 F2 48 89 E5 53 48 89 FB 48 83 EC 20 48 8B 47 08 44 8B 5D 28 48 8B B0 70 04 00 00 48 8B 38 31 C0 45 85 DB";
                  
    // Select the appropriate patterns based on the architecture
    //var pattern_mb_derive_secret =  "F3 0F 1E FA 48 89 B7 D8 03 00 00 C3"; //set_ctx
    console.log("[*] Using HKDF pattern: "+pattern_mb_derive_secret)

    // Try first pattern and if it fails, try the second one
    hook_HKDF_By_Unique_Pattern(moduleBase, moduleSize, pattern_mb_derive_secret, "derive_secret");
    //var pattern_prf = "41 57 41 56 41 55 49 89 D5 41 54 49 89 F4 55 53 48 89 FB 48 81 EC B8 01 00 00 48 8B 84 24 F8 01 00 00 48 89 0C 24 4C 89 44 24 08 4C 8B BC 24 08 02 00 00 48 89 44 24 18 48 8B 84 24 18 02 00 00 4C 89 4C 24 10 48 89 44 24 20 64 48 8B 04 25 28 00 00 00 48 89 84 24 A8 01 00 00 31 C0 E8 CE 31 F9 FF";
    // OpenSSL 3 system baseline identified by TLSKeyHunter/Ghidra from the
    // "extended master secret" reference (Ghidra offset 0x00152070).
    var pattern_prf = "55 48 89 E5 41 57 41 56 41 55 41 54 49 89 FC 53 48 81 EC C8 01 00 00 48 8B 45 38 48 89 B5 40 FE FF FF 48 89 95 38 FE FF FF 4C 8B 75 18 48 89 8D 30 FE FF FF 4C 8B 7D 28 4C 89 85 28 FE FF FF 4C 89 8D 20 FE FF FF 48 89 85 48 FE FF FF 64 48 8B 04 25 28 00 00 00 48 89 45 C8 31 C0 E8 BF 53 FE FF";
    hook_PRF_By_Pattern(moduleBase, moduleSize, pattern_prf, "pattern_prf_secret");
}

function hook_HKDF_By_Unique_Pattern(moduleBase, moduleSize, pattern, pattern_name) {
    var matches = Memory.scanSync(moduleBase, moduleSize, pattern);
    console.log("[TLSKH_FINGERPRINT] id=" + pattern_name + " matches=" + matches.length);
    if (matches.length !== 1) {
        console.log("[TLSKH_REJECT] id=" + pattern_name + " reason=required_exactly_one_pattern_match");
        return;
    }
    var address = matches[0].address;
    console.log("Pattern found at (" + pattern_name + "): " + address);
    Interceptor.attach(address, {
        onEnter: function (args) {
            var ranker = getArgRanker();
            this.argSnapshot = captureArgs(args, 12);
            this.labelCandidate = selectCandidate(
                ranker.rankLabelCandidates(this.argSnapshot, {
                    callSite: "openssl_tls13_hkdf_label",
                    maxArgs: 12,
                    labels: tlsLabelMapping
                }),
                this.argSnapshot,
                3,
                "tls13_label"
            );
            if (!this.labelCandidate) {
                this.skipExtraction = true;
                return;
            }
            this.beforeHexByIndex = rankerMode() === "D"
                ? captureBeforeHexByIndex(
                    this.argSnapshot,
                    TLS13_SECRET_LENGTH,
                    [this.labelCandidate.index]
                )
                : {};
        },
        onLeave: function (retval) {
            if (this.skipExtraction || retval.isNull()) {
                return;
            }
            var ranker = getArgRanker();
            var candidates = [];
            if (rankerMode() === "D") {
                candidates = ranker.rankSecretCandidates(
                    this.argSnapshot,
                    [TLS13_SECRET_LENGTH],
                    {
                        callSite: "openssl_tls13_hkdf_secret",
                        maxArgs: 12,
                        excludeIndexes: [this.labelCandidate.index],
                        beforeHexByIndex: this.beforeHexByIndex
                    }
                );
                candidates.forEach(function (candidate) {
                    console.log(
                        "[TLSKH_RANK_CANDIDATE] kind=secret mode=D index=" + candidate.index +
                        " score=" + candidate.score +
                        " length=" + candidate.length +
                        " reasons=" + candidate.reasons.join(",")
                    );
                });
            }
            var secretCandidate = selectSecretCandidate(
                candidates,
                this.argSnapshot,
                9,
                "tls13_secret"
            );
            if (secretCandidate) {
                var canonicalLabel = this.labelCandidate.mappedLabel;
                var secretHex = candidateHex(secretCandidate, TLS13_SECRET_LENGTH);
                if (canonicalLabel && secretHex.length === TLS13_SECRET_LENGTH * 2) {
                    console.log("[TLSKH_CANDIDATE] " + canonicalLabel + " " + secretHex);
                } else {
                    console.log("[TLSKH_REJECT] tls13_secret reason=label_or_length");
                }
            }
        }
    });
}


function hook_HKDF_By_Pattern(moduleBase, moduleSize, pattern, pattern_name){

    Memory.scan(moduleBase, moduleSize, pattern, {
                    onMatch: function(address, size) {
                        console.log("Pattern found at ("+pattern_name+"): " + address);
                        
                        // Hook the function using Interceptor
	                        Interceptor.attach(address, {
	                            onEnter: function(args) {
	                                var ranker = getArgRanker();
	                                this.argSnapshot = captureArgs(args, 12);

	                                this.labelCandidate = selectCandidate(
	                                    ranker.rankLabelCandidates(this.argSnapshot, {
	                                        callSite: "openssl_tls13_hkdf",
	                                        maxArgs: 12,
	                                        fallbackIndex: 7,
	                                        preferredIndexes: [7],
	                                        labels: tlsLabelMapping
	                                    }),
	                                    this.argSnapshot,
	                                    7,
	                                    "tls13_label"
	                                );
	                                if (!this.labelCandidate) {
	                                    this.skipExtraction = true;
	                                    return;
	                                }

	                                this.connectionCandidate = selectCandidate(
	                                    ranker.rankStructureCandidates(this.argSnapshot, {
	                                        callSite: "openssl_tls13_hkdf",
	                                        maxArgs: 12,
	                                        fallbackIndex: 0,
	                                        preferredIndexes: [0],
	                                        excludeIndexes: [this.labelCandidate.index]
	                                    }),
	                                    this.argSnapshot,
	                                    0,
	                                    "tls13_connection"
	                                );
	                                if (!this.connectionCandidate) {
	                                    this.skipExtraction = true;
	                                    return;
	                                }

	                                this.sc = this.connectionCandidate.pointer; // ptr to SSL_Connection struct
	                                this.label = this.labelCandidate.pointer; // ptr to the label string

	                                /*
	                                if(!this.label.isNull()){
                                     var mylabel = this.label.readCString();
                                     console.log("[!] Label: "+mylabel);

                                }*/


                               
                                // Initialize an empty array to store arguments
                                /*
                                if(did_check == false){
                                    this.myargs = [];
                                    this.myargs = get_working_func_args(args,true, true);
                                }*/
                                


                            },
                            onLeave: function(retval) {
                                



	                                if (!retval.isNull() && !this.skipExtraction) {

                                    /*
                                    if(did_check == false){
                                        console.log("automation test start---------------------------");
                                        console.log("We identified "+this.myargs.length+" number of arguments");
                                        console.log(" now beginning wit the check...");
                                        // Analyze the saved arguments from `onEnter`
                                        try {
                                            for (var i = 0; i < this.myargs.length; i++) {
                                                var arg = this.myargs[i];
                                                if (arg) {
                                                    console.log('Argument ' + i + ' onLeave:');
                                                    dumpMemory(arg, 0x180); // Optional: Dump memory at argument address
                                                    console.log("Start checking arguments....");
                                                    check_arguments(arg, i);
                                                } else {
                                                    console.log('Argument ' + i + ' is null or invalid onLeave.');
                                                }
                                            }
                                        } catch (e) {
                                            console.log('[!] Error in onLeave: ' + e.message);
                                            did_check = false;
                                        }

                                        console.log("------------ Leave part end ---------");

                                        did_check = false;

                                    }  */


                                    // working version for TLS 1.3
                                    // currently the EXPORTER_SECRET is not derived using this method
                                    /*
                                    In future release this func:
                                    https://github.com/openssl/openssl/blob/b049ce0e354011be075e620b9ba7cf4d7c8f9577/ssl/tls13_enc.c#L689
                                    the exporter is directly derived using the tls13_hkdf_expand

                                    In the next paper it should improved so that if we identify the string used for traffc secrets result into
                                    the same function as one used for the exporter secret
                                    */
	                                    var ranker = getArgRanker();
	                                    var secretCandidate = selectSecretCandidate(
	                                        ranker.rankSecretCandidates(this.argSnapshot, [TLS13_SECRET_LENGTH], {
	                                            callSite: "openssl_tls13_hkdf",
	                                            maxArgs: 12,
	                                            fallbackIndex: 9,
	                                            preferredIndexes: [9],
	                                            excludeIndexes: [this.labelCandidate.index, this.connectionCandidate.index]
	                                        }),
	                                        this.argSnapshot,
	                                        9,
	                                        "tls13_secret"
	                                    );
	                                    if (!secretCandidate) {
	                                        return;
	                                    }

	                                    this.key = secretCandidate.pointer;
	                                    if(session_client_random.length < 2){
	                                        session_client_random = get_client_random_from_ssl_connection(this.label, this.sc);
	                                    }
		                                    dump_keys_from_derive_secrets(session_client_random, this.key, this.label, secretCandidate.length || TLS13_SECRET_LENGTH);

	                                }
                            }
                        });
                    }
                });
}


function hook_PRF_By_Pattern(moduleBase, moduleSize, pattern, pattern_name){
    var matches = Memory.scanSync(moduleBase, moduleSize, pattern);
    console.log(
        "[TLSKH_FINGERPRINT] id=" + pattern_name + " matches=" + matches.length
    );
    if (matches.length !== 1) {
        console.log(
            "[TLSKH_REJECT] id=" + pattern_name +
            " reason=required_exactly_one_pattern_match"
        );
        return;
    }
    var address = matches[0].address;
    console.log("Pattern found at ("+pattern_name+"): " + address);
    Interceptor.attach(address, {
	                            onEnter: function(args) {
	                                this.dump_keys = false;
	                                var ranker = getArgRanker();
	                                this.argSnapshot = captureArgs(args, 12);
	                                this.secretBefore = {};
	                                if (rankerMode() === "D") {
	                                    for (var secretIndex = 0; secretIndex < 12; secretIndex++) {
	                                        var beforeBytes = safeReadByteArray(
	                                            this.argSnapshot[secretIndex],
	                                            TLS12_MASTER_SECRET_LENGTH
	                                        );
	                                        if (beforeBytes !== null) {
	                                            this.secretBefore[secretIndex] = byteArrayToHex(beforeBytes);
	                                        }
	                                    }
	                                }
	                                this.labelCandidate = selectCandidate(
	                                    ranker.rankLabelCandidates(this.argSnapshot, {
	                                        callSite: "openssl_tls12_prf",
	                                        maxArgs: 12,
	                                        fallbackIndex: 1,
	                                        usePreferredIndexes: false,
	                                        labels: tlsLabelMapping
	                                    }),
	                                    this.argSnapshot,
	                                    1,
	                                    "tls12_label"
	                                );
	                                if (!this.labelCandidate) {
	                                    return;
	                                }

	                                var selectedLabel = this.labelCandidate.label || safeReadCString(this.labelCandidate.pointer, 64);
	                                if(selectedLabel && ["master secret", "extended master secret"].indexOf(selectedLabel.toLowerCase()) !== -1){
	                                    this.lengthCandidate = selectCandidate(
	                                        ranker.rankIntegerCandidates(this.argSnapshot, {
	                                            callSite: "openssl_tls12_prf",
	                                            maxArgs: 12,
	                                            fallbackIndex: 10,
	                                            usePreferredIndexes: false,
	                                            expectedValues: [TLS12_MASTER_SECRET_LENGTH]
	                                        }),
	                                        this.argSnapshot,
	                                        10,
	                                        "tls12_length"
	                                    );
	                                    if (!this.lengthCandidate) {
	                                        return;
	                                    }

	                                    this.key_length = TLS12_MASTER_SECRET_LENGTH;
	                                    this.dump_keys = true;
	                                }

	                                /*
	                                if(did_check == false){
                                    this.myargs = [];
                                    this.myargs = get_working_func_args(args,true, true);
                                    this.dump_keys = true;
                                }
                                /*  */


                            },
                            onLeave: function(retval) {
                

	                                if (!retval.isNull() && this.dump_keys) {
	                                    var ranker = getArgRanker();
	                                    var secretCandidates = [];
	                                    if (rankerMode() === "D") {
	                                        secretCandidates = ranker.rankSecretCandidates(
	                                            this.argSnapshot,
	                                            [TLS12_MASTER_SECRET_LENGTH],
	                                            {
	                                                callSite: "openssl_tls12_prf",
	                                                maxArgs: 12,
	                                                beforeHexByIndex: this.secretBefore,
	                                                excludeIndexes: [this.labelCandidate.index]
	                                            }
	                                        );
	                                    }
	                                    var secretCandidate = selectSecretCandidate(
	                                        secretCandidates,
	                                        this.argSnapshot,
	                                        9,
	                                        "tls12_secret"
	                                    );
	                                    if (!secretCandidate) {
	                                        this.dump_keys = false;
	                                        return;
	                                    }

	                                    this.key = secretCandidate.pointer;
	                                    var candidateBytes = safeReadByteArray(
	                                        this.key,
	                                        secretCandidate.length || this.key_length
	                                    );
	                                    if (candidateBytes !== null) {
	                                        console.log(
	                                            "[TLSKH_CANDIDATE] CLIENT_RANDOM " +
	                                            byteArrayToHex(candidateBytes).toUpperCase()
	                                        );
	                                    }
	                                    this.dump_keys = false;

                                    /* 
                                    if(did_check == false){
                                        console.log("------------- Key Identificaiton -------------");
                                        console.log("[*] We identified "+this.myargs.length+" number of arguments");
                                        // Analyze the saved arguments from `onEnter`
                                        try {
                                            for (var i = 0; i < this.myargs.length; i++) {
                                                var arg = this.myargs[i];
                                                if (arg) {
                                                    console.log('[*] Checking Argument: ' + i);
                                                    dumpMemory(arg, 0x180);
                                                    check_arguments(arg, i);
                                                } else {
                                                    console.log('[!] Argument ' + i + ' is null or invalid.');
                                                }
                                            }
                                        } catch (e) {
                                            console.log('[!] Error in onLeave: ' + e.message);
                                            did_check = false;
                                        }

                                        did_check = false;

                                    } */
                               
                                
                                }
                            }
    });
} 

// Find the OpenSSL module
function findOpenSSLModule() {
    var modules = Process.enumerateModules();
    for (var i = 0; i < modules.length; i++) {
        var name = modules[i].name;
        if (name.startsWith("libssl") ) {
            console.log("Found OpenSSL Module: " + name);
            return modules[i];
        }
    }
    console.log("OpenSSL module not found.");
    return null;
}


// test_client_13_boringssl_key_export
// Main function
function main() {
    var module = findOpenSSLModule();
    if (module !== null) {
        hookOpenSSLByPattern(module);
    }
}

// Run the main function
main();


/*
In OpenSSL
https://github.com/google/boringssl/blob/5a94aff9aebcf9738c7bc464bc95fa4ac3a46ed7/ssl/tls13_enc.cc#L323

[*] HKDF-Function identified with label: DERIVE_SECRET_KEY_AND_IV
[*] String (Register R9) used as 6th argument in function call at address: 0x00425b53 (invoking DERIVE_SECRET_KEY_AND_IV)
[*] Function offset (Ghidra): 00424EC0 (0x00424EC0)
[*] Function offset (IDA with base 0x0): 00324EC0 (0x00324EC0)
[*] Byte pattern for frida (friTap): 41 57 4D 89 CF 41 56 41 89 CE 41 55 4D 89 C5 41 54 49 89 D4 55 48 89 FD 48 89 F7 53 48 89 F3 48 83 EC 08 E8 28 D4 0C 00

[*] PRF-Function identified with label: TLS1_PRF.CONSTPROP.0
[*] String (Register RSI) used as 2th argument in function call at address: 0x00477bca (invoking TLS1_PRF.CONSTPROP.0)
[*] Function offset (Ghidra): 00476DB0 (0x00476DB0)
[*] Function offset (IDA with base 0x0): 00376DB0 (0x00376DB0)
[*] Byte pattern for frida (friTap): 41 57 41 56 41 55 49 89 D5 41 54 49 89 F4 55 53 48 89 FB 48 81 EC B8 01 00 00 48 8B 84 24 F8 01 00 00 48 89 0C 24 4C 89 44 24 08 4C 8B BC 24 08 02 00 00 48 89 44 24 18 48 8B 84 24 18 02 00 00 4C 89 4C 24 10 48 89 44 24 20 64 48 8B 04 25 28 00 00 00 48 89 84 24 A8 01 00 00 31 C0 E8 CE 35 F9 FF



neueste variante
https://github.com/openssl/openssl/blob/85f17585b0d8b55b335f561e2862db14a20b1e64/ssl/tls13_enc.c#L347C1-L347C7


[*] HKDF-Function identified with label: DERIVE_SECRET_KEY_AND_IV
[*] String (Register R9) used as 5th argument in function call at address: 0x00425e23 (invoking DERIVE_SECRET_KEY_AND_IV)
[*] We tracked also a copy operation of the previous register: RAX used as -1th argument
[*] Function offset (Ghidra): 00425190 (0x00425190)
[*] Function offset (IDA with base 0x0): 00325190 (0x00325190)
[*] Byte pattern for frida: 41 57 4D 89 CF 41 56 41 89 CE 41 55 4D 89 C5 41 54 49 89 D4 55 48 89 FD 48 89 F7 53 48 89 F3 48 83 EC 08 E8 48 D5 0C 00


[*] Start identifying the PRF by looking for String "master secret"

[*] String master secret wasn't found in binary! Trying another approach...
[*] Start identifying the PRF by looking for String "extended master secret"
[!] Found String at ref: 00477ffc
[!] Instruction used there: LEA RSI,[0x8774c0]
[!] Analyzing instruction at reference address: LEA RSI,[0x8774c0]
[!] Reference stored in register: RSI
[!] Using infos for analysis: CALL 0x00477200
[!] analysis (0): CALL 0x00477200
[*] String (Register RSI) used as 1th argument in function call at address: 0x0047801a (invoking TLS1_PRF.CONSTPROP.0)
[*] PRF function identified: TLS1_PRF.CONSTPROP.0
[!!!] Functionname: ssl_prf_md (Signature: undefined ssl_prf_md(void))


entweder diese hier:
https://github.com/openssl/openssl/blob/4d41cc910306868285b89bd4b95d79bac693a630/ssl/t1_enc.c#L392 --> das wo es aufgerufen wird

https://github.com/openssl/openssl/blob/4d41cc910306868285b89bd4b95d79bac693a630/ssl/t1_enc.c#L25 -- die function


[*] PRF-Function identified with label: TLS1_PRF.CONSTPROP.0
[*] String (Register RSI) used as 1th argument in function call at address: 0x0047801a (invoking TLS1_PRF.CONSTPROP.0)
[*] Function offset (Ghidra): 00477200 (0x00477200)
[*] Function offset (IDA with base 0x0): 00377200 (0x00377200)
[*] Byte pattern for frida: 41 57 41 56 41 55 49 89 D5 41 54 49 89 F4 55 53 48 89 FB 48 81 EC B8 01 00 00 48 8B 84 24 F8 01 00 00 48 89 0C 24 4C 89 44 24 08 4C 8B BC 24 08 02 00 00 48 89 44 24 18 48 8B 84 24 18 02 00 00 4C 89 4C 24 10 48 89 44 24 20 64 48 8B 04 25 28 00 00 00 48 89 84 24 A8 01 00 00 31 C0 E8 CE 31 F9 FF



Currently the hooking of the HKDF seems to block the target binary therefore I have to do the following in order to solve it:
- Ensure your Frida script precisely hooks the intended functions without causing unintended side effects. Double-check that the hooks are properly applied and not blocking or altering function calls.
Use debug logging in your Frida script to confirm that the correct function is hooked and invoked as expected.

Reason: OpenSSL relies on thread-local storage and specific execution contexts. Frida hooks might modify or affect these contexts, leading to functions like derive_secret not being called.
Solution:

    Check if the SSL_CTX or SSL objects have the correct callbacks set after Frida injects itself. You can inspect the SSL_CTX_set_keylog_callback or similar settings in your hook to confirm they are not altered.



Auch mal mit den Patterns von
https://github.com/openssl/openssl/blob/85f17585b0d8b55b335f561e2862db14a20b1e64/ssl/tls13_enc.c#L121

sowie
https://github.com/openssl/openssl/blob/85f17585b0d8b55b335f561e2862db14a20b1e64/ssl/tls13_enc.c#L99

versuchen


./test_client_13_openssl_debug
Starting client
Press Enter to proceed...

DEBUG: TLS_client_method() 
DEBUG: SSL_CTX_new() 
DEBUG: SSL_CTX_set_min_proto_version() 
DEBUG: SSL_CTX_set_max_proto_version() 
Established TCP connection
DEBUG: SSL_new() 
DEBUG: SSL_set_fd 
DEBUG: SSL_connect() 
Established TLS connection
Connected to 127.0.0.1:4433. Press Enter to disconnect...

DEBUG: SSL_shutdown() 
DEBUG: SSL_free() 
DEBUG: SSL_CTX_free() 


und mit hooken:
./test_client_13_openssl_debug
Starting client
Press Enter to proceed...

DEBUG: TLS_client_method() 
DEBUG: SSL_CTX_new() 
DEBUG: SSL_CTX_set_min_proto_version() 
DEBUG: SSL_CTX_set_max_proto_version() 
Established TCP connection
DEBUG: SSL_new() 
DEBUG: SSL_set_fd 
^C


*/
