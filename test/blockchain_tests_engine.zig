// Copyright (c) 2025-2026 zevm authors
// SPDX-License-Identifier: MIT OR Apache-2.0

const std = @import("std");
const zevm = @import("zevm");
const types = zevm.types;
const engine = zevm.engine;
const rpc = zevm.engine_rpc;
const hex = rpc.hex;
const utils = @import("utils.zig");

const Hash = hex.Data(32);

// engine_newPayloadVX params: [payload, versionedHashes, parentBeaconBlockRoot, executionRequests?]
const NewPayloadParams = struct {
    payload: rpc.ExecutionPayload,
    versioned_hashes: []Hash,
    parent_beacon_block_root: Hash,
    execution_requests: []hex.Bytes,

    pub fn jsonParse(allocator: std.mem.Allocator, source: anytype, options: std.json.ParseOptions) !@This() {
        if (try source.next() != .array_begin) return error.UnexpectedToken;
        var out: @This() = .{
            .payload = try std.json.innerParse(rpc.ExecutionPayload, allocator, source, options),
            .versioned_hashes = try std.json.innerParse([]Hash, allocator, source, options),
            .parent_beacon_block_root = try std.json.innerParse(Hash, allocator, source, options),
            .execution_requests = &.{},
        };
        if (try source.peekNextTokenType() != .array_end) {
            out.execution_requests = try std.json.innerParse([]hex.Bytes, allocator, source, options);
        }
        if (try source.next() != .array_end) return error.UnexpectedToken;
        return out;
    }
};

const EngineNewPayload = struct {
    params: NewPayloadParams,
    newPayloadVersion: []const u8,
    forkchoiceUpdatedVersion: []const u8,
    validationError: ?[]const u8 = null,
    errorCode: ?[]const u8 = null,
};

const GenesisHeader = struct {
    parentHash: Hash,
    uncleHash: Hash,
    coinbase: hex.Data(20),
    stateRoot: Hash,
    transactionsTrie: Hash,
    receiptTrie: Hash,
    bloom: hex.Data(256),
    difficulty: utils.HexInt(u256),
    number: utils.HexInt(u64),
    gasLimit: utils.HexInt(u64),
    gasUsed: utils.HexInt(u64),
    timestamp: utils.HexInt(u64),
    extraData: utils.HexBytes,
    mixHash: Hash,
    nonce: hex.Data(8),
    baseFeePerGas: ?utils.HexInt(u64) = null,
    withdrawalsRoot: ?Hash = null,
    blobGasUsed: ?utils.HexInt(u64) = null,
    excessBlobGas: ?utils.HexInt(u64) = null,
    parentBeaconBlockRoot: ?Hash = null,
    requestsHash: ?Hash = null,
    blockAccessListHash: ?Hash = null,
    slotNumber: ?utils.HexInt(u64) = null,
    hash: Hash,

    fn toHeader(self: GenesisHeader) !types.BlockHeader {
        if (self.extraData.value.len > 32) return error.ExtraDataTooLong;
        var extra_data: types.ExtraData = .{ .buf = undefined, .len = self.extraData.value.len };
        @memcpy(extra_data.buf[0..extra_data.len], self.extraData.value);
        return .{
            .parent_hash = self.parentHash.bytes,
            .ommers_hash = self.uncleHash.bytes,
            .beneficiary = self.coinbase.bytes,
            .state_root = self.stateRoot.bytes,
            .transactions_root = self.transactionsTrie.bytes,
            .receipts_root = self.receiptTrie.bytes,
            .logs_bloom = self.bloom.bytes,
            .difficulty = self.difficulty.value,
            .number = self.number.value,
            .gas_limit = self.gasLimit.value,
            .gas_used = self.gasUsed.value,
            .timestamp = self.timestamp.value,
            .extra_data = extra_data,
            .mix_hash = self.mixHash.bytes,
            .nonce = self.nonce.bytes,
            .base_fee_per_gas = if (self.baseFeePerGas) |v| v.value else null,
            .withdrawals_root = if (self.withdrawalsRoot) |v| v.bytes else null,
            .blob_gas_used = if (self.blobGasUsed) |v| v.value else null,
            .excess_blob_gas = if (self.excessBlobGas) |v| v.value else null,
            .parent_beacon_block_root = if (self.parentBeaconBlockRoot) |v| v.bytes else null,
            .requests_hash = if (self.requestsHash) |v| v.bytes else null,
            .block_access_list_hash = if (self.blockAccessListHash) |v| v.bytes else null,
            .slot_number = if (self.slotNumber) |v| v.value else null,
        };
    }
};

const EngineTest = struct {
    network: []const u8,
    genesisBlockHeader: GenesisHeader,
    pre: std.json.ArrayHashMap(utils.AccountState),
    lastblockhash: ?Hash = null,
    config: utils.Config = .{},
    engineNewPayloads: []EngineNewPayload,
    _info: ?utils.Info = null,
};

const EngineTestFile = std.json.ArrayHashMap(EngineTest);

fn newPayload(
    eng: *engine.Engine,
    arena: std.mem.Allocator,
    params: *const NewPayloadParams,
) !engine.PayloadStatus {
    const payload = try params.payload.toExecutionPayload(arena);

    const versioned_hashes = try arena.alloc([32]u8, params.versioned_hashes.len);
    for (params.versioned_hashes, versioned_hashes) |src, *dst| dst.* = src.bytes;

    const requests = try arena.alloc([]const u8, params.execution_requests.len);
    for (params.execution_requests, requests) |src, *dst| dst.* = src.bytes;

    return eng.newPayload(
        arena,
        &payload,
        versioned_hashes,
        params.parent_beacon_block_root.bytes,
        requests,
    );
}

// Mirrors the error -> JSON-RPC code mapping in Server.handle (src/rpc/jsonrpc.zig).
fn rpcErrorCode(err: anyerror) i32 {
    return switch (err) {
        error.InvalidJSON => -32700,
        error.InvalidRequest => -32600,
        error.MethodNotFound => -32601,
        error.InvalidParams => -32602,
        else => -32603,
    };
}

fn expectForkchoiceValid(eng: *engine.Engine, allocator: std.mem.Allocator, head: [32]u8) !void {
    const resp = try eng.forkchoiceUpdated(allocator, .{
        .head_block_hash = head,
        .safe_block_hash = @splat(0),
        .finalized_block_hash = @splat(0),
    });
    if (resp.status != .valid) return error.UnexpectedForkchoiceStatus;
}

// Follows the hive EEST engine simulator (consume/simulators/simulator_logic/test_via_engine.py).
fn runEngineTest(gpa: std.mem.Allocator, test_case: *const EngineTest) !void {
    var committed = try utils.buildCommittedState(gpa, test_case.pre);
    defer committed.deinit();

    const genesis = try test_case.genesisBlockHeader.toHeader();
    if (!std.mem.eql(u8, &genesis.hash(), &test_case.genesisBlockHeader.hash.bytes)) {
        return error.GenesisHashMismatch;
    }

    var eng: engine.Engine = .{};

    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();

    // Initial forkchoice update to genesis to establish the chain head.
    try expectForkchoiceValid(&eng, arena.allocator(), test_case.genesisBlockHeader.hash.bytes);

    for (test_case.engineNewPayloads) |*entry| {
        _ = arena.reset(.retain_capacity);
        const valid = entry.validationError == null;

        if (newPayload(&eng, arena.allocator(), &entry.params)) |resp| {
            const expected_status: engine.PayloadStatus.Status = if (valid) .valid else .invalid;
            if (resp.status != expected_status) return error.UnexpectedPayloadStatus;
            if (entry.errorCode != null) return error.ExpectedErrorCode;
            if (resp.status == .invalid) {
                const got = resp.validation_error orelse return error.MissingValidationError;
                if (!utils.exceptionMatches(got, entry.validationError.?)) return got;
            }
        } else |err| {
            const expected_code = entry.errorCode orelse return err;
            if (rpcErrorCode(err) != try std.fmt.parseInt(i32, expected_code, 10)) return err;
        }

        // For valid payloads, advance the chain head.
        if (valid) try expectForkchoiceValid(&eng, arena.allocator(), entry.params.payload.blockHash.bytes);
    }
}

fn fileWorker(io: std.Io, allocator: std.mem.Allocator, dir: std.Io.Dir, path: []const u8, fork: []const u8, any_failed: *std.atomic.Value(bool)) void {
    runEngineTestFile(io, allocator, dir, path, fork) catch {
        any_failed.store(true, .release);
    };
}

fn runEngineTestFile(io: std.Io, allocator: std.mem.Allocator, dir: std.Io.Dir, path: []const u8, fork: []const u8) !void {
    const file = try dir.openFile(io, path, .{});
    defer file.close(io);

    var buf: [1024]u8 = undefined;
    var reader = file.reader(io, &buf);
    const contents = try reader.interface.allocRemaining(allocator, .unlimited);
    defer allocator.free(contents);

    const parsed = std.json.parseFromSlice(EngineTestFile, allocator, contents, .{
        .ignore_unknown_fields = true,
    }) catch |e| {
        std.debug.print("failed to parse {s}\n", .{path});
        return e;
    };
    defer parsed.deinit();

    var any_failed = false;
    for (parsed.value.map.keys(), parsed.value.map.values()) |name, test_case| {
        if (!std.mem.eql(u8, test_case.network, fork)) {
            continue;
        }

        runEngineTest(allocator, &test_case) catch |err| {
            std.debug.print("{s}: FAIL: {}\n", .{ name, err });
            any_failed = true;
        };
    }
    if (any_failed) return error.EngineTestFailed;
}

test "blockchain engine tests" {
    var gpa = std.heap.DebugAllocator(.{ .thread_safe = true }){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    const io = std.testing.io;

    const fork = std.mem.span(std.c.getenv("FORK").?);
    if (std.c.getenv("ENGINE_TEST")) |cpath| {
        try runEngineTestFile(io, allocator, std.Io.Dir.cwd(), std.mem.span(cpath), fork);
        return;
    }

    var lowercase_fork: [64]u8 = undefined;
    var fixtures_path: [128]u8 = undefined;
    var dir = try std.Io.Dir.cwd().openDir(
        io,
        try std.fmt.bufPrint(&fixtures_path, "fixtures/blockchain_tests_engine/for_{s}", .{
            std.ascii.lowerString(&lowercase_fork, fork),
        }),
        .{ .iterate = true },
    );
    defer dir.close(io);

    var paths: std.ArrayListUnmanaged([]u8) = .empty;
    defer {
        for (paths.items) |p| allocator.free(p);
        paths.deinit(allocator);
    }
    {
        var walker = try dir.walk(allocator);
        defer walker.deinit();
        while (try walker.next(io)) |entry| {
            if (entry.kind != .file) continue;
            if (!std.mem.endsWith(u8, entry.path, ".json")) continue;
            try paths.append(allocator, try allocator.dupe(u8, entry.path));
        }
    }

    var any_failed = std.atomic.Value(bool).init(false);
    var pool: std.Io.Group = .init;
    for (paths.items) |path| {
        pool.async(io, fileWorker, .{ io, allocator, dir, path, fork, &any_failed });
    }
    try pool.await(io);

    if (any_failed.load(.acquire)) return error.EngineTestFailed;
}
