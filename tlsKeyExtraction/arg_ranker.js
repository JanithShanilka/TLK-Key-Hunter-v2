(function (global) {
    "use strict";

    const DEFAULT_MAX_ARGS = 12;
    const DEFAULT_MINIMUM_SCORES = {
        secret: 65,
        label: 60,
        client_random: 50,
        integer: 50,
        structure: 50
    };
    const DEFAULT_LABELS = {
        "c ap traffic": "CLIENT_TRAFFIC_SECRET_0",
        "s ap traffic": "SERVER_TRAFFIC_SECRET_0",
        "c hs traffic": "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
        "s hs traffic": "SERVER_HANDSHAKE_TRAFFIC_SECRET",
        "e traffic": "EARLY_TRAFFIC_SECRET",
        "master secret": "MASTER_SECRET",
        "extended master secret": "MASTER_SECRET",
        "exp master": "EXPORTER_SECRET",
        "key expansion": "CLIENT_RANDOM"
    };

    const selectionHistory = {};

    function pointerString(pointerValue) {
        try {
            return String(pointerValue);
        } catch (e) {
            return "<unprintable>";
        }
    }

    function pointerLooksSane(pointerValue) {
        try {
            if (pointerValue === null || pointerValue === undefined || pointerValue.isNull()) {
                return false;
            }

            const value = pointerValue.toString().replace(/^0x/i, "").replace(/^0+/, "");
            return value.length > 3;
        } catch (e) {
            return false;
        }
    }

    function getArg(args, index) {
        try {
            return args[index];
        } catch (e) {
            return null;
        }
    }

    function readBytes(pointerValue, length) {
        try {
            if (!pointerLooksSane(pointerValue)) {
                return null;
            }
            Memory.readU8(pointerValue);
            return Memory.readByteArray(pointerValue, length);
        } catch (e) {
            return null;
        }
    }

    function readCString(pointerValue, maxLength) {
        try {
            if (!pointerLooksSane(pointerValue)) {
                return null;
            }
            Memory.readU8(pointerValue);
            return pointerValue.readCString(maxLength || 64);
        } catch (e) {
            return null;
        }
    }

    function bytesToHex(byteArray) {
        if (byteArray === null || byteArray === undefined) {
            return "";
        }
        return Array
            .from(new Uint8Array(byteArray))
            .map(function (byte) { return byte.toString(16).padStart(2, "0").toUpperCase(); })
            .join("");
    }

    function countZeroBytes(byteArray) {
        const bytes = new Uint8Array(byteArray);
        let count = 0;
        for (let i = 0; i < bytes.length; i++) {
            if (bytes[i] === 0) {
                count++;
            }
        }
        return count;
    }

    function shannonEntropy(byteArray) {
        const bytes = new Uint8Array(byteArray);
        const counts = new Array(256).fill(0);
        for (let i = 0; i < bytes.length; i++) {
            counts[bytes[i]]++;
        }

        let entropy = 0;
        for (let i = 0; i < counts.length; i++) {
            if (counts[i] === 0) {
                continue;
            }
            const probability = counts[i] / bytes.length;
            entropy -= probability * (Math.log(probability) / Math.log(2));
        }
        return entropy;
    }

    function normalizeExpectedLengths(expectedLengths, context) {
        if (Array.isArray(expectedLengths)) {
            return expectedLengths;
        }
        if (typeof expectedLengths === "number") {
            return [expectedLengths];
        }
        if (context && Array.isArray(context.expectedLengths)) {
            return context.expectedLengths;
        }
        return [];
    }

    function maxArgs(context) {
        return context && context.maxArgs ? context.maxArgs : DEFAULT_MAX_ARGS;
    }

    function isExcluded(index, context) {
        return !!(context && context.excludeIndexes && context.excludeIndexes.indexOf(index) !== -1);
    }

    function hasPreferredIndex(index, context) {
        return !!(context && context.preferredIndexes && context.preferredIndexes.indexOf(index) !== -1);
    }

    function historyKey(type, context) {
        const callSite = context && context.callSite ? context.callSite : "default";
        return type + ":" + callSite;
    }

    function minimumScore(type, context) {
        if (context && typeof context.minimumScore === "number") {
            return context.minimumScore;
        }
        return DEFAULT_MINIMUM_SCORES[type];
    }

    function finish(type, candidates, context) {
        const key = historyKey(type, context);
        const previousIndex = selectionHistory[key];

        candidates.forEach(function (candidate) {
            if (candidate.index === previousIndex) {
                candidate.score += 10;
                candidate.reasons.push("stable_across_calls");
            }
        });

        candidates.sort(function (a, b) { return b.score - a.score; });
        const eligible = candidates.filter(function (candidate) {
            return candidate.score >= minimumScore(type, context);
        });

        if (eligible.length > 0) {
            selectionHistory[key] = eligible[0].index;
        }

        return eligible;
    }

    function rankSecretCandidates(args, expectedLengths, context) {
        const lengths = normalizeExpectedLengths(expectedLengths, context);
        const candidates = [];

        for (let i = 0; i < maxArgs(context); i++) {
            if (isExcluded(i, context)) {
                continue;
            }

            const pointerValue = getArg(args, i);
            for (let j = 0; j < lengths.length; j++) {
                const length = lengths[j];
                const bytes = readBytes(pointerValue, length);
                if (bytes === null) {
                    continue;
                }

                const entropy = shannonEntropy(bytes);
                const zeroBytes = countZeroBytes(bytes);
                const reasons = ["readable", "length_" + length];
                let score = 40;

                if (entropy >= 4.0) {
                    score += 25;
                    reasons.push("high_entropy");
                }
                if (zeroBytes <= Math.max(2, Math.floor(length / 8))) {
                    score += 10;
                    reasons.push("low_zero_count");
                }
                const currentHex = bytesToHex(bytes);
                const beforeHex = context && context.beforeHexByIndex
                    ? context.beforeHexByIndex[i]
                    : null;
                if (beforeHex && String(beforeHex).toUpperCase() !== currentHex) {
                    score += 20;
                    reasons.push("changed_during_call");
                }

                candidates.push({
                    index: i,
                    pointer: pointerValue,
                    pointerString: pointerString(pointerValue),
                    score: score,
                    reasons: reasons,
                    length: length,
                    hex: currentHex
                });
            }
        }

        return finish("secret", candidates, context);
    }

    function selectUniqueCandidate(candidates) {
        if (!candidates || candidates.length === 0) {
            return { status: "no_candidate", candidate: null, tiedIndexes: [] };
        }

        const topScore = candidates[0].score;
        const tied = candidates.filter(function (candidate) {
            return candidate.score === topScore;
        });
        if (tied.length !== 1) {
            return {
                status: "ambiguous_top_score",
                candidate: null,
                tiedIndexes: tied.map(function (candidate) { return candidate.index; })
            };
        }

        return { status: "selected", candidate: tied[0], tiedIndexes: [] };
    }

    function rankLabelCandidates(args, context) {
        const labels = context && context.labels ? context.labels : DEFAULT_LABELS;
        const candidates = [];

        for (let i = 0; i < maxArgs(context); i++) {
            if (isExcluded(i, context)) {
                continue;
            }

            const pointerValue = getArg(args, i);
            const label = readCString(pointerValue, 64);
            if (!label) {
                continue;
            }

            const normalized = label.toLowerCase();
            let matchedLabel = null;
            Object.keys(labels).some(function (knownLabel) {
                if (normalized === knownLabel || normalized.indexOf(knownLabel) === 0) {
                    matchedLabel = knownLabel;
                    return true;
                }
                return false;
            });
            const reasons = ["readable_string"];
            let score = 20;

            if (matchedLabel !== null) {
                score += 50;
                reasons.push(normalized === matchedLabel ? "known_tls_label" : "known_tls_label_prefix");
            }
            if (!(context && context.usePreferredIndexes === false) && hasPreferredIndex(i, context)) {
                score += 20;
                reasons.push("preferred_label_arg");
            }

            candidates.push({
                index: i,
                pointer: pointerValue,
                pointerString: pointerString(pointerValue),
                score: score,
                reasons: reasons,
                label: matchedLabel || label,
                mappedLabel: matchedLabel === null ? null : labels[matchedLabel]
            });
        }

        return finish("label", candidates, context);
    }

    function rankClientRandomCandidates(args, expectedLengths, context) {
        if (!context && expectedLengths && !Array.isArray(expectedLengths)) {
            context = expectedLengths;
            expectedLengths = [32];
        }

        const lengths = normalizeExpectedLengths(expectedLengths, context);
        const offsets = context && context.offsets ? context.offsets : [0];
        const candidates = [];

        for (let i = 0; i < maxArgs(context); i++) {
            if (isExcluded(i, context)) {
                continue;
            }

            const pointerValue = getArg(args, i);
            for (let o = 0; o < offsets.length; o++) {
                const offset = offsets[o];
                let readPointer = pointerValue;
                try {
                    readPointer = offset === 0 ? pointerValue : pointerValue.add(offset);
                } catch (e) {
                    continue;
                }

                for (let j = 0; j < lengths.length; j++) {
                    const length = lengths[j];
                    const bytes = readBytes(readPointer, length);
                    if (bytes === null) {
                        continue;
                    }

                    const zeroBytes = countZeroBytes(bytes);
                    const entropy = shannonEntropy(bytes);
                    const reasons = ["readable", "length_" + length];
                    let score = 35;

                    if (!(context && context.useZeroCount === false) && zeroBytes < length) {
                        score += 10;
                        reasons.push("not_all_zero");
                    }
                    if (!(context && context.useEntropy === false) && entropy >= 3.0) {
                        score += 10;
                        reasons.push("random_like");
                    }
                    if (offset !== 0) {
                        reasons.push("offset_" + offset.toString(16));
                    }
                    if (!(context && context.usePreferredIndexes === false) && hasPreferredIndex(i, context)) {
                        score += 25;
                        reasons.push("preferred_client_random_arg");
                    }

                    candidates.push({
                        index: i,
                        pointer: readPointer,
                        pointerString: pointerString(readPointer),
                        basePointer: pointerValue,
                        score: score,
                        reasons: reasons,
                        length: length,
                        offset: offset,
                        hex: bytesToHex(bytes)
                    });
                }
            }
        }

        return finish("client_random", candidates, context);
    }

    function rankIntegerCandidates(args, context) {
        const expectedValues = context && context.expectedValues ? context.expectedValues : [];
        const candidates = [];

        for (let i = 0; i < maxArgs(context); i++) {
            if (isExcluded(i, context)) {
                continue;
            }

            const value = getArg(args, i);
            let intValue;
            try {
                intValue = value.toInt32();
            } catch (e) {
                continue;
            }

            const reasons = ["integer_like"];
            let score = 10;

            if (!pointerLooksSane(value)) {
                score += 10;
                reasons.push("small_value");
            }
            if (expectedValues.indexOf(intValue) !== -1) {
                score += 40;
                reasons.push("expected_value_" + intValue);
            }
            if (!(context && context.usePreferredIndexes === false) && hasPreferredIndex(i, context)) {
                score += 20;
                reasons.push("preferred_length_arg");
            }

            candidates.push({
                index: i,
                pointer: value,
                pointerString: pointerString(value),
                score: score,
                reasons: reasons,
                value: intValue
            });
        }

        return finish("integer", candidates, context);
    }

    function rankStructureCandidates(args, context) {
        const candidates = [];

        for (let i = 0; i < maxArgs(context); i++) {
            if (isExcluded(i, context)) {
                continue;
            }

            const pointerValue = getArg(args, i);
            const bytes = readBytes(pointerValue, 8);
            if (bytes === null) {
                continue;
            }

            const reasons = ["readable_header"];
            let score = 30;

            if (!(context && context.usePreferredIndexes === false) && hasPreferredIndex(i, context)) {
                score += 30;
                reasons.push("preferred_structure_arg");
            }

            candidates.push({
                index: i,
                pointer: pointerValue,
                pointerString: pointerString(pointerValue),
                score: score,
                reasons: reasons
            });
        }

        return finish("structure", candidates, context);
    }

    global.ArgRanker = {
        rankSecretCandidates: rankSecretCandidates,
        selectUniqueCandidate: selectUniqueCandidate,
        rankLabelCandidates: rankLabelCandidates,
        rankClientRandomCandidates: rankClientRandomCandidates,
        rankIntegerCandidates: rankIntegerCandidates,
        rankStructureCandidates: rankStructureCandidates,
        bytesToHex: bytesToHex,
        readBytes: readBytes,
        readCString: readCString,
        pointerLooksSane: pointerLooksSane,
        minimumScore: minimumScore,
        resetHistory: function () {
            Object.keys(selectionHistory).forEach(function (key) {
                delete selectionHistory[key];
            });
        }
    };
})(typeof globalThis !== "undefined" ? globalThis : this);
