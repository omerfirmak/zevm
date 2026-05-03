const std = @import("std");
const zevm = @import("zevm");
const evm = zevm.evm;
const state_mod = zevm.state;
const types = zevm.types;
const spec = zevm.spec;
const rlp = @import("rlp");
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

pub const Transaction = struct {
    sender: utils.HexInt(u160),
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
    var gpa = std.heap.DebugAllocator(.{ .thread_safe = true }){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    const io = std.testing.io;

    const fork = std.mem.span(std.c.getenv("FORK").?);
    if (std.c.getenv("STATE_TEST")) |cpath| {
        const path = std.mem.span(cpath);
        if (std.c.getenv("TRACE")) |_| {
            try runStateTestFile(io, allocator, std.Io.Dir.cwd(), path, fork, true);
        } else {
            try runStateTestFile(io, allocator, std.Io.Dir.cwd(), path, fork, false);
        }
        return;
    }

    var lowercase_fork: [64]u8 = undefined;
    var fixtures_path: [128]u8 = undefined;
    var dir = try std.Io.Dir.cwd().openDir(
        io,
        try std.fmt.bufPrint(&fixtures_path, "fixtures/state_tests/for_{s}", .{
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

    if (any_failed.load(.acquire)) return error.StateTestFailed;
}

fn fileWorker(io: std.Io, allocator: std.mem.Allocator, dir: std.Io.Dir, path: []const u8, fork: []const u8, any_failed: *std.atomic.Value(bool)) void {
    runStateTestFile(io, allocator, dir, path, fork, false) catch {
        any_failed.store(true, .release);
    };
}

fn runStateTestFile(io: std.Io, allocator: std.mem.Allocator, dir: std.Io.Dir, path: []const u8, fork: []const u8, comptime trace: bool) !void {
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
        _ = test_case.post.map.get(fork) orelse continue;

        const test_err = runStateTest(allocator, &test_case, fork, trace);
        test_err catch |err| {
            std.debug.print("{s}: FAIL: {}\n", .{ name, err });
            any_failed = true;
        };
    }
    if (any_failed) return error.StateTestFailed;
}

fn runStateTest(gpa: std.mem.Allocator, test_case: *const StateTest, fork: []const u8, comptime trace: bool) !void {
    const tx = test_case.transaction;
    const forkSpec = spec.specByFork(utils.forkFromString(fork));
    const post_entries = test_case.post.map.get(fork).?;

    const blob_schedule = if (test_case.config.blobSchedule) |bs| bs.map.get(fork) else null;
    const blob_update_fraction: u64 = if (blob_schedule) |s| s.baseFeeUpdateFraction.value else 0;
    const max_blobs: u64 = if (blob_schedule) |s| s.max.value else 0;

    for (post_entries) |post_entry| {
        var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
        defer arena.deinit();
        var logs_allocator = std.heap.ArenaAllocator.init(std.heap.page_allocator);
        defer logs_allocator.deinit();
        var logs: std.DoublyLinkedList = .{};

        var committed = try utils.buildCommittedState(gpa, test_case.pre);
        defer committed.deinit();

        const arena_allocator = arena.allocator();

        var ancestors = [_]u256{0} ** 256;
        if (test_case.env.previousHash) |h| ancestors[0] = h.value;
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

        var state: state_mod.State = undefined;
        var vm: evm.EVM = undefined;

        const tx_err: ?anyerror = blk: {
            const txbytes = (post_entry.txbytes orelse break :blk error.MissingTxBytes).value;
            var decoded_tx: types.Transaction = undefined;
            _ = rlp.deserialize(types.Transaction, arena_allocator, txbytes, &decoded_tx) catch |e| break :blk e;

            const gas_limit: u64 = switch (decoded_tx) {
                inline else => |t| @intCast(t.gas_limit),
            };
            state = try state_mod.State.init(arena_allocator, &committed, forkSpec.stateCapacities(gas_limit));
            vm = try evm.EVM.init(arena_allocator, logs_allocator.allocator(), &logs, &context, forkSpec.evmCapacities());

            const msg = zevm.processor.messageFromTx(arena_allocator, &decoded_tx, tx.sender.value) catch |e| break :blk e;
            break :blk switch (utils.forkFromString(fork)) {
                inline else => |f| if (vm.process(.{ .fork = spec.specByFork(f), .tracing_enabled = trace }, &msg, &state)) |_| null else |err| err,
            };
        };

        if (post_entry.expectException) |expected| {
            const actual = tx_err orelse return error.ExpectedExceptionButSucceeded;
            if (!utils.exceptionMatches(actual, expected)) return actual;
            continue;
        } else if (tx_err) |err| {
            return err;
        }

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
