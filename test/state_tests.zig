const std = @import("std");
const zevm = @import("zevm");
const evm = zevm.evm;
const state_mod = zevm.state;
const types = zevm.types;
const spec = zevm.spec;
const CommittedState = @import("committed_state").CommittedState;
const utils = @import("utils.zig");

pub const Env = struct {
    currentCoinbase: utils.HexInt(u160),
    currentGasLimit: utils.HexInt(u64),
    currentNumber: utils.HexInt(u64),
    currentTimestamp: utils.HexInt(u64),
    currentRandom: ?utils.HexInt(u256) = null,
    previousHash: ?utils.HexInt(u256) = null,
    currentDifficulty: utils.HexInt(u256),
    currentBaseFee: ?utils.HexInt(u256) = null,
    currentExcessBlobGas: ?utils.HexInt(u64) = null,
};

pub const AccessListEntry = struct {
    address: utils.HexInt(u160),
    storageKeys: []utils.HexInt(u256),
};

pub const AuthorizationTuple = struct {
    chainId: utils.HexInt(u256),
    address: utils.HexInt(u160),
    nonce: utils.HexInt(u64),
    signer: ?utils.HexInt(u160) = null,
    v: ?utils.HexInt(u64) = null,
    yParity: ?utils.HexInt(u64) = null,
    r: ?utils.HexBytes = null,
    s: ?utils.HexBytes = null,
};

pub const Transaction = struct {
    nonce: utils.HexInt(u64),
    gasPrice: ?utils.HexInt(u256) = null,
    // EIP-1559 (type 2) fee fields
    maxFeePerGas: ?utils.HexInt(u256) = null,
    maxPriorityFeePerGas: ?utils.HexInt(u256) = null,
    gasLimit: []utils.HexInt(u64),
    to: ?utils.HexAddress = null,
    value: []utils.HexInt(u256),
    data: []utils.HexBytes,
    sender: utils.HexInt(u160),
    secretKey: ?utils.HexBytes = null,
    // EIP-2930: one access list per data index (parallel to data[]/gasLimit[]/value[])
    accessLists: ?[][]AccessListEntry = null,
    // EIP-4844: blob transaction fields
    maxFeePerBlobGas: ?utils.HexInt(u256) = null,
    blobVersionedHashes: ?[]utils.HexInt(u256) = null,
    // EIP-7702: authorization list (type-4 tx)
    authorizationList: ?[]AuthorizationTuple = null,
};

pub const PostIndexes = struct {
    data: u32,
    gas: u32,
    value: u32,
};

pub const PostEntry = struct {
    hash: utils.HexBytes,
    logs: utils.HexBytes,
    txbytes: ?utils.HexBytes = null,
    indexes: PostIndexes,
    state: ?std.json.ArrayHashMap(utils.AccountState) = null,
    expectException: ?[]const u8 = null,
};

pub const StateTest = struct {
    env: Env,
    pre: std.json.ArrayHashMap(utils.AccountState),
    transaction: Transaction,
    post: std.json.ArrayHashMap([]PostEntry),
    config: utils.Config = .{},
    _info: ?utils.Info = null,
};

// Top-level JSON is a map of test name -> StateTest
pub const StateTestFile = std.json.ArrayHashMap(StateTest);

test "state tests" {
    const supported_forks = [_][]const u8{"Osaka"};

    var gpa = std.heap.DebugAllocator(.{ .thread_safe = true }){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    const io = std.testing.io;

    if (std.c.getenv("STATE_TEST")) |cpath| {
        const path = std.mem.span(cpath);
        if (std.c.getenv("TRACE")) |_| {
            try runStateTestFile(io, allocator, std.Io.Dir.cwd(), path, supported_forks[0..], true);
        } else {
            try runStateTestFile(io, allocator, std.Io.Dir.cwd(), path, supported_forks[0..], false);
        }
        return;
    }

    var dir = try std.Io.Dir.cwd().openDir(io, "fixtures/state_tests", .{ .iterate = true });
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
        pool.async(io, fileWorker, .{ io, allocator, dir, path, supported_forks[0..], &any_failed });
    }
    try pool.await(io);

    if (any_failed.load(.acquire)) return error.StateTestFailed;
}

fn fileWorker(io: std.Io, allocator: std.mem.Allocator, dir: std.Io.Dir, path: []const u8, forks: []const []const u8, any_failed: *std.atomic.Value(bool)) void {
    runStateTestFile(io, allocator, dir, path, forks, false) catch {
        any_failed.store(true, .release);
    };
}

fn runStateTestFile(io: std.Io, allocator: std.mem.Allocator, dir: std.Io.Dir, path: []const u8, forks: []const []const u8, comptime trace: bool) !void {
    const file = try dir.openFile(io, path, .{});
    defer file.close(io);

    var buf: [1024]u8 = undefined;
    var reader = file.reader(io, &buf);
    const contents = try reader.interface.allocRemaining(allocator, .unlimited);
    defer allocator.free(contents);

    const parsed = std.json.parseFromSlice(StateTestFile, allocator, contents, .{
        .ignore_unknown_fields = true,
    }) catch |e| {
        std.debug.print("failed to parse {s}\n", .{path});
        return e;
    };
    defer parsed.deinit();

    var any_failed = false;
    for (parsed.value.map.keys(), parsed.value.map.values()) |name, test_case| {
        for (forks) |fork| {
            _ = test_case.post.map.get(fork) orelse continue;

            const test_err = runStateTest(allocator, &test_case, fork, trace);
            test_err catch |err| {
                std.debug.print("{s}: FAIL: {}\n", .{ name, err });
                any_failed = true;
            };
        }
    }
    if (any_failed) return error.StateTestFailed;
}

fn runStateTest(gpa: std.mem.Allocator, test_case: *const StateTest, fork: []const u8, comptime trace: bool) !void {
    const tx = test_case.transaction;
    const forkSpec = spec.Osaka;

    const post_entries = test_case.post.map.get(fork).?;

    // EIP-4844: build blob versioned hashes slice for context (BLOBHASH opcode)
    const blob_hashes: []u256 = if (tx.blobVersionedHashes) |bvh| blk: {
        const hashes = try gpa.alloc(u256, bvh.len);
        for (bvh, hashes) |src, *dst| {
            dst.* = src.value;
        }
        break :blk hashes;
    } else &.{};
    defer if (tx.blobVersionedHashes != null) gpa.free(blob_hashes);

    // EIP-4844: get blob schedule for this fork
    const blob_schedule = if (test_case.config.blobSchedule) |bs| bs.map.get(fork) else null;
    const blob_update_fraction: u64 = if (blob_schedule) |s| s.baseFeeUpdateFraction.value else 0;
    const max_blobs: u64 = if (blob_schedule) |s| s.max.value else 0;

    // EIP-7702: build authorization list
    // secp256k1 n/2: s must be in [1, N/2] per EIP-2 style check in EIP-7702
    const secp256k1_n_half: u256 = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0;
    const auth_list: ?[]evm.Authorization = if (tx.authorizationList) |al| blk: {
        const list = try gpa.alloc(evm.Authorization, al.len);
        for (al, list) |src, *dst| {
            // Invalid if signer missing (ecrecover failed), or s out of EIP-2 range
            const s_invalid = if (src.s) |s_bytes| s_blk: {
                var s_val: u256 = 0;
                for (s_bytes.value) |b| s_val = (s_val << 8) | b;
                break :s_blk s_val == 0 or s_val > secp256k1_n_half;
            } else false;
            // chain_id > u64 max will never match current chain (which is u64)
            const chain_id: u64 = if (src.chainId.value > std.math.maxInt(u64)) std.math.maxInt(u64) else @intCast(src.chainId.value);
            dst.* = .{
                .chain_id = chain_id,
                .address = src.address.value,
                .nonce = src.nonce.value,
                .authority = if (src.signer == null or s_invalid) 0 else src.signer.?.value,
            };
        }
        break :blk list;
    } else null;
    defer if (tx.authorizationList != null) gpa.free(auth_list.?);

    for (post_entries) |post_entry| {
        var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
        defer arena.deinit();
        var logs_allocator = std.heap.ArenaAllocator.init(std.heap.page_allocator);
        defer logs_allocator.deinit();
        var logs: std.DoublyLinkedList = .{};

        // Build committed state from pre-state
        var committed = try utils.buildCommittedState(gpa, test_case.pre);
        defer committed.deinit();

        const arena_allocator = arena.allocator();
        var state = try state_mod.State.init(arena_allocator, &committed, 10_000_000);

        const gas_limit = tx.gasLimit[post_entry.indexes.gas].value;
        const value = tx.value[post_entry.indexes.value].value;
        const calldata = tx.data[post_entry.indexes.data].value;

        // convert parsed access list entries to evm.AccessListEntry for this tx variant
        const raw_al: []AccessListEntry = if (tx.accessLists) |als|
            if (post_entry.indexes.data < als.len) als[post_entry.indexes.data] else &.{}
        else
            &.{};
        const access_list = try gpa.alloc(evm.AccessListEntry, raw_al.len);
        var al_count: usize = 0;
        defer {
            for (access_list[0..al_count]) |entry| gpa.free(entry.storage_keys);
            gpa.free(access_list);
        }
        for (raw_al, access_list) |src, *dst| {
            const keys = try gpa.alloc(u256, src.storageKeys.len);
            for (src.storageKeys, keys) |k, *out| out.* = k.value;
            dst.* = .{ .address = src.address.value, .storage_keys = keys };
            al_count += 1;
        }

        const to: ?u160 = if (tx.to) |t| t.value else null; // HexAddress.value is ?u160; null JSON or empty string both yield null
        var ancestors = [_]u256{0} ** 256;
        if (test_case.env.previousHash) |previousHash| {
            ancestors[0] = previousHash.value;
        }
        const context = evm.Context{
            .chainid = 1,
            .number = test_case.env.currentNumber.value,
            .coinbase = test_case.env.currentCoinbase.value,
            .time = test_case.env.currentTimestamp.value,
            .random = if (test_case.env.currentRandom) |r| r.value else 0,
            .gas_limit = test_case.env.currentGasLimit.value,
            .basefee = test_case.env.currentBaseFee.?.value,
            .blob_base_fee = if (test_case.env.currentExcessBlobGas) |ebg| zevm.blobBaseFee(ebg.value, blob_update_fraction) else 0,
            .max_blobs_per_block = max_blobs,
            .ancestors = ancestors,
        };
        var vm = try evm.EVM.init(
            arena_allocator,
            logs_allocator.allocator(),
            &logs,
            &.{
                .caller = tx.sender.value,
                .nonce = tx.nonce.value,
                .target = to,
                .gas_limit = @intCast(gas_limit),
                .gas_price = if (tx.gasPrice) |gp| gp.value else null,
                .max_fee_per_gas = if (tx.maxFeePerGas) |mfpg| mfpg.value else null,
                .max_priority_fee_per_gas = if (tx.maxPriorityFeePerGas) |mpfpg| mpfpg.value else null,
                .calldata = calldata,
                .value = value,
                .access_list = access_list,
                .max_fee_per_blob_gas = if (tx.maxFeePerBlobGas) |mfpbg| mfpbg.value else null,
                .blob_versioned_hashes = blob_hashes,
                .authorization_list = auth_list,
            },
            &context,
        );

        const tx_err: ?anyerror = if (vm.process(.{
            .fork = forkSpec,
            .tracing_enabled = trace,
        }, &state)) |_| null else |err| err;

        if (post_entry.expectException) |expected| {
            const actual = tx_err orelse return error.ExpectedExceptionButSucceeded;
            if (!utils.exceptionMatches(actual, expected)) return actual;
            continue;
        } else if (tx_err) |err| {
            return err;
        }

        // Verify logs hash.
        if (post_entry.logs.value.len == 32 and !std.mem.allEqual(u8, post_entry.logs.value, 0)) {
            const actual_logs_hash = try evm.computeLogsHash(gpa, &logs);
            if (!std.mem.eql(u8, &actual_logs_hash, post_entry.logs.value)) {
                return error.LogsHashMismatch;
            }
        }

        const trie_buf = try gpa.alloc(u8, 16 * 1024 * 1024);
        defer gpa.free(trie_buf);
        var trie_fba = std.heap.FixedBufferAllocator.init(trie_buf);

        const actual_root = try utils.computeStateRoot(gpa, &trie_fba, &state, &committed, &vm);
        if (!std.mem.allEqual(u8, post_entry.logs.value, 0) and !std.mem.eql(u8, &actual_root, post_entry.hash.value)) {
            return error.StateRootHashMismatch;
        }
        if (trace) {
            std.debug.print("{{\"stateRoot\":\"0x{s}\"}}\n", .{std.fmt.bytesToHex(actual_root, .lower)});
        }
    }
}
