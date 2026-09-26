"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

class MockPointer {
    constructor(address, bytes, text, intValue, offset = 0) {
        this.address = address;
        this.bytes = bytes ? Buffer.from(bytes) : null;
        this.text = text;
        this.intValue = intValue;
        this.offset = offset;
    }

    isNull() {
        return this.address === 0;
    }

    toString() {
        return `0x${this.address.toString(16)}`;
    }

    toInt32() {
        if (this.intValue === undefined) {
            throw new Error("not an integer");
        }
        return this.intValue;
    }

    readCString() {
        if (this.text === undefined) {
            throw new Error("not a string");
        }
        return this.text;
    }

    add(offset) {
        return new MockPointer(
            this.address + offset,
            this.bytes,
            this.text,
            this.intValue,
            this.offset + offset
        );
    }
}

global.Memory = {
    readU8(pointer) {
        if (!(pointer instanceof MockPointer) || pointer.isNull()) {
            throw new Error("unreadable");
        }
        return 0;
    },

    readByteArray(pointer, length) {
        if (!(pointer instanceof MockPointer) || pointer.bytes === null) {
            throw new Error("unreadable");
        }
        const start = pointer.offset || 0;
        if (pointer.bytes.length < start + length) {
            throw new Error("short read");
        }
        return pointer.bytes.subarray(start, start + length);
    }
};

const rankerPath = path.join(__dirname, "..", "tlsKeyExtraction", "arg_ranker.js");
vm.runInThisContext(fs.readFileSync(rankerPath, "utf8"), { filename: rankerPath });
const ranker = global.ArgRanker;

function pointer(address, bytes) {
    return new MockPointer(address, bytes);
}

function stringPointer(address, text) {
    return new MockPointer(address, Buffer.alloc(64), text);
}

function integer(value) {
    return new MockPointer(value, null, undefined, value);
}

function deterministicBytes(length, seed = 17) {
    return Buffer.from(Array.from({ length }, (_, index) => (index * 73 + seed) % 256));
}

let testsRun = 0;

function test(name, body) {
    ranker.resetHistory();
    body();
    testsRun += 1;
    process.stdout.write(`ok - ${name}\n`);
}

test("accepts a readable high-entropy secret of the expected length", () => {
    const args = [pointer(0x1000, deterministicBytes(32))];
    const candidates = ranker.rankSecretCandidates(args, [32], {
        maxArgs: 1,
        usePreferredIndexes: false
    });
    assert.equal(candidates.length, 1);
    assert.equal(candidates[0].index, 0);
    assert.ok(candidates[0].score >= ranker.minimumScore("secret"));
});

test("returns no candidate for low-entropy zero-filled data", () => {
    const args = [pointer(0x1000, Buffer.alloc(32))];
    assert.deepEqual(
        ranker.rankSecretCandidates(args, [32], {
            maxArgs: 1,
            usePreferredIndexes: false
        }),
        []
    );
});

test("returns no candidate for invalid or unreadable pointers", () => {
    const args = [new MockPointer(0), pointer(0x2000, Buffer.alloc(4))];
    assert.deepEqual(
        ranker.rankSecretCandidates(args, [32], { maxArgs: 2 }),
        []
    );
});

test("accepts known TLS labels and rejects unrelated strings", () => {
    const known = ranker.rankLabelCandidates(
        [stringPointer(0x1000, "c hs traffic")],
        { maxArgs: 1, usePreferredIndexes: false }
    );
    assert.equal(known[0].mappedLabel, "CLIENT_HANDSHAKE_TRAFFIC_SECRET");

    const unknown = ranker.rankLabelCandidates(
        [stringPointer(0x2000, "not a tls label")],
        { maxArgs: 1, usePreferredIndexes: false }
    );
    assert.deepEqual(unknown, []);
});

test("recognizes a known TLS label at the start of a byte span", () => {
    const candidates = ranker.rankLabelCandidates(
        [stringPointer(0x2100, "extended master secretTRAILING")],
        { maxArgs: 1, usePreferredIndexes: false }
    );
    assert.equal(candidates.length, 1);
    assert.equal(candidates[0].label, "extended master secret");
    assert.equal(candidates[0].mappedLabel, "MASTER_SECRET");
    assert.ok(candidates[0].reasons.includes("known_tls_label_prefix"));
});

test("uses repeated-call consistency in the full ranker", () => {
    const key = deterministicBytes(32);
    ranker.rankSecretCandidates(
        [new MockPointer(0), pointer(0x2000, key)],
        [32],
        { maxArgs: 2, callSite: "repeat", minimumScore: 0, usePreferredIndexes: false }
    );

    const withConsistency = ranker.rankSecretCandidates(
        [pointer(0x1000, key), pointer(0x2000, key)],
        [32],
        { maxArgs: 2, callSite: "repeat", minimumScore: 0, usePreferredIndexes: false }
    );
    assert.equal(withConsistency[0].index, 1);
    assert.ok(withConsistency[0].reasons.includes("stable_across_calls"));

});

test("uses an intra-call buffer change as temporal consistency evidence", () => {
    const unchanged = deterministicBytes(32, 9);
    const changed = deterministicBytes(32, 11);
    const candidates = ranker.rankSecretCandidates(
        [pointer(0x1000, unchanged), pointer(0x2000, changed)],
        [32],
        {
            maxArgs: 2,
            callSite: "mutation",
            usePreferredIndexes: false,
            beforeHexByIndex: {
                0: unchanged.toString("hex"),
                1: deterministicBytes(32, 12).toString("hex")
            }
        }
    );
    assert.equal(candidates[0].index, 1);
    assert.ok(candidates[0].reasons.includes("changed_during_call"));
});

test("always applies entropy and zero-count in the full ranker", () => {
    const candidates = ranker.rankSecretCandidates(
        [pointer(0x1000, deterministicBytes(32))],
        [32],
        {
            maxArgs: 1,
            useEntropy: false,
            useZeroCount: false
        }
    );
    assert.equal(candidates[0].score, 75);
    assert.ok(candidates[0].reasons.includes("high_entropy"));
    assert.ok(candidates[0].reasons.includes("low_zero_count"));
});

test("does not use preferred index scoring for secret candidates", () => {
    const candidates = ranker.rankSecretCandidates(
        [pointer(0x1000, deterministicBytes(32)), pointer(0x2000, deterministicBytes(32, 23))],
        [32],
        { maxArgs: 2, preferredIndexes: [1] }
    );
    assert.equal(candidates[0].score, candidates[1].score);
    assert.ok(!candidates[1].reasons.includes("preferred_output_arg"));
});

test("refuses an ambiguous top score", () => {
    const candidates = ranker.rankSecretCandidates(
        [pointer(0x1000, deterministicBytes(32)), pointer(0x2000, deterministicBytes(32, 23))],
        [32],
        { maxArgs: 2, callSite: "tie" }
    );
    const decision = ranker.selectUniqueCandidate(candidates);
    assert.equal(decision.status, "ambiguous_top_score");
    assert.equal(decision.candidate, null);
    assert.deepEqual(decision.tiedIndexes, [0, 1]);
});

test("requires expected integer values at the default confidence threshold", () => {
    const rejected = ranker.rankIntegerCandidates([integer(7)], {
        maxArgs: 1,
        expectedValues: [48],
        usePreferredIndexes: false
    });
    assert.deepEqual(rejected, []);

    const accepted = ranker.rankIntegerCandidates([integer(48)], {
        maxArgs: 1,
        expectedValues: [48],
        usePreferredIndexes: false
    });
    assert.equal(accepted[0].value, 48);
});

test("requires structural preference at the default confidence threshold", () => {
    const args = [pointer(0x1000, deterministicBytes(8))];
    assert.deepEqual(
        ranker.rankStructureCandidates(args, {
            maxArgs: 1,
            usePreferredIndexes: false
        }),
        []
    );

    const accepted = ranker.rankStructureCandidates(args, {
        maxArgs: 1,
        preferredIndexes: [0]
    });
    assert.equal(accepted[0].index, 0);
});

process.stdout.write(`${testsRun} arg_ranker tests passed\n`);
