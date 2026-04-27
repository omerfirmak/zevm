const std = @import("std");
const zevm = @import("zevm");
const types = zevm.types;
const state_mod = zevm.state;
const rlp = @import("rlp");
const utils = @import("utils.zig");

// Parses only the sender address from a transaction JSON object.
const TxSender = struct {
    sender: utils.HexInt(u160),
};

// One entry in the "blocks" array. Valid blocks have no expectException; invalid
// blocks (which leave the state unchanged) carry an expectException string.
const BlockEntry = struct {
    rlp: utils.HexBytes,
    transactions: ?[]TxSender = null,
    expectException: ?[]const u8 = null,
};

// Reuses the same Config shape as state tests (blobSchedule + chainid).
const BlockchainTest = struct {
    network: []const u8,
    genesisRLP: utils.HexBytes,
    pre: std.json.ArrayHashMap(utils.AccountState),
    postState: ?std.json.ArrayHashMap(utils.AccountState) = null,
    lastblockhash: ?utils.HexBytes = null,
    config: utils.Config = .{},
    blocks: []BlockEntry,
    _info: ?utils.Info = null,
};

const BlockchainTestFile = std.json.ArrayHashMap(BlockchainTest);

fn prepareBlock(
    arena: std.mem.Allocator,
    block_entry: BlockEntry,
) !zevm.processor.PreprocessedBlock {
    var block: types.Block = undefined;
    _ = try rlp.deserialize(types.Block, arena, block_entry.rlp.value, &block);

    var senders = try arena.alloc(u160, block.transactions.len);
    if (block_entry.transactions) |json_txs| {
        senders = try arena.alloc(u160, json_txs.len);
        for (json_txs, senders) |tx, *s| s.* = tx.sender.value;
    }

    return .{
        .block = block,
        .senders = senders,
        .rlp_size = block_entry.rlp.value.len,
        .txhashes = &.{},
    };
}

fn runBlockchainTest(gpa: std.mem.Allocator, test_case: *const BlockchainTest) !void {
    var committed = try utils.buildCommittedState(gpa, test_case.pre);
    defer committed.deinit();

    var genesis_arena = std.heap.ArenaAllocator.init(gpa);
    const arena_allocator = genesis_arena.allocator();
    defer genesis_arena.deinit();
    var parent: types.Block = blk: {
        var block: types.Block = undefined;
        _ = try rlp.deserialize(types.Block, genesis_arena.allocator(), test_case.genesisRLP.value, &block);
        break :blk block;
    };

    var state = try state_mod.State.init(arena_allocator, &committed, 10_000_000);
    defer state.deinit(arena_allocator);

    // ancestor_chain[k] = parent_hash of the block that is k+1 levels below the current parent.
    // Invariant: ancestors[0] for the next block = prepared.block.header.parent_hash (read directly);
    //            ancestors[k] for k>=1 = ancestor_chain[k-1].
    var ancestor_chain: [255][32]u8 = undefined;
    var ancestor_chain_len: usize = 0;

    for (test_case.blocks) |block_entry| {
        var arena = std.heap.ArenaAllocator.init(gpa);
        defer arena.deinit();

        const validate_err: ?anyerror, const prepared: ?zevm.processor.PreprocessedBlock = blk: {
            const p = prepareBlock(arena.allocator(), block_entry) catch |e| break :blk .{ e, null };
            var ancestors = [_]u256{0} ** 256;
            ancestors[0] = std.mem.readInt(u256, &p.block.header.parent_hash, .big);
            for (0..@min(ancestor_chain_len, 255)) |k| {
                ancestors[k + 1] = std.mem.readInt(u256, &ancestor_chain[k], .big);
            }
            const proc_err: ?anyerror = if (zevm.processor.processBlock(
                arena.allocator(),
                gpa,
                zevm.chainspec.Osaka,
                &p,
                &parent.header,
                ancestors,
                &state,
            )) |_| null else |err| err;
            break :blk .{ proc_err, p };
        };

        if (block_entry.expectException) |expected| {
            const actual = validate_err orelse return error.ExpectedExceptionButSucceeded;
            if (!utils.exceptionMatches(actual, expected)) return actual;
            continue;
        } else if (validate_err) |err| {
            return err;
        }

        const ok = prepared.?;
        const new_len = @min(ancestor_chain_len + 1, 255);
        std.mem.copyBackwards([32]u8, ancestor_chain[1..new_len], ancestor_chain[0 .. new_len - 1]);
        ancestor_chain[0] = ok.block.header.parent_hash;
        ancestor_chain_len = new_len;

        parent = ok.block;
    }
}

fn fileWorker(io: std.Io, allocator: std.mem.Allocator, dir: std.Io.Dir, path: []const u8, forks: []const []const u8, any_failed: *std.atomic.Value(bool)) void {
    runBlockchainTestFile(io, allocator, dir, path, forks) catch {
        any_failed.store(true, .release);
    };
}

fn runBlockchainTestFile(io: std.Io, allocator: std.mem.Allocator, dir: std.Io.Dir, path: []const u8, forks: []const []const u8) !void {
    const file = try dir.openFile(io, path, .{});
    defer file.close(io);

    var buf: [1024]u8 = undefined;
    var reader = file.reader(io, &buf);
    const contents = try reader.interface.allocRemaining(allocator, .unlimited);
    defer allocator.free(contents);

    const parsed = std.json.parseFromSlice(BlockchainTestFile, allocator, contents, .{
        .ignore_unknown_fields = true,
    }) catch |e| {
        std.debug.print("failed to parse {s}\n", .{path});
        return e;
    };
    defer parsed.deinit();

    var any_failed = false;
    for (parsed.value.map.keys(), parsed.value.map.values()) |name, test_case| {
        var matches_fork = false;
        for (forks) |fork| {
            if (std.mem.eql(u8, test_case.network, fork)) {
                matches_fork = true;
                break;
            }
        }
        if (!matches_fork) continue;

        runBlockchainTest(allocator, &test_case) catch |err| {
            std.debug.print("{s}: FAIL: {}\n", .{ name, err });
            any_failed = true;
        };
    }
    if (any_failed) return error.BlockchainTestFailed;
}

test "blockchain tests" {
    const supported_forks = [_][]const u8{"Osaka"};

    var gpa = std.heap.DebugAllocator(.{ .thread_safe = true }){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    const io = std.testing.io;

    if (std.c.getenv("BLOCKCHAIN_TEST")) |cpath| {
        try runBlockchainTestFile(io, allocator, std.Io.Dir.cwd(), std.mem.span(cpath), supported_forks[0..]);
        return;
    }

    var dir = try std.Io.Dir.cwd().openDir(io, "fixtures/blockchain_tests", .{ .iterate = true });
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

    if (any_failed.load(.acquire)) return error.BlockchainTestFailed;
}
