const std = @import("std");
const zevm = @import("zevm");
const types = zevm.types;
const state_mod = zevm.state;
const rlp = @import("rlp");
const utils = @import("utils.zig");

const SlotChange = struct {
    blockAccessIndex: utils.HexInt(u32),
    postValue: utils.HexInt(u256),
};

const StorageChange = struct {
    slot: utils.HexInt(u256),
    slotChanges: []SlotChange,
};

const BalanceChange = struct {
    blockAccessIndex: utils.HexInt(u32),
    postBalance: utils.HexInt(u256),
};

const NonceChange = struct {
    blockAccessIndex: utils.HexInt(u32),
    postNonce: utils.HexInt(u64),
};

const CodeChange = struct {
    blockAccessIndex: utils.HexInt(u32),
    newCode: utils.HexBytes,
};

const AccountAccessList = struct {
    address: utils.HexInt(u160),
    storageChanges: []StorageChange,
    storageReads: []utils.HexInt(u256),
    balanceChanges: []BalanceChange,
    nonceChanges: []NonceChange,
    codeChanges: []CodeChange,
};

// Some fixture formats nest blockAccessList under rlp_decoded.
const RlpDecoded = struct {
    blockAccessList: ?[]AccountAccessList = null,
    transactions: ?[]Transaction = null,
};

const Transaction = struct {
    sender: utils.HexInt(u160),
};

// One entry in the "blocks" array. Valid blocks have no expectException; invalid
// blocks (which leave the state unchanged) carry an expectException string.
const BlockEntry = struct {
    rlp: utils.HexBytes,
    expectException: ?[]const u8 = null,
    transactions: ?[]Transaction = null,
    // Older fixture format: direct field.
    blockAccessList: ?[]AccountAccessList = null,
    // Newer fixture format: nested under rlp_decoded.
    rlp_decoded: ?RlpDecoded = null,
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

    const bal: ?types.BlockAccessLists = blk: {
        const json_bal = block_entry.blockAccessList orelse
            if (block_entry.rlp_decoded) |rd| (rd.blockAccessList orelse break :blk null) else break :blk null;

        const result = try arena.alloc(types.AccountChanges, json_bal.len);
        for (json_bal, result) |src, *dst| {
            dst.addr = src.address.value;

            dst.storage_changes = try arena.alloc(types.SlotChanges, src.storageChanges.len);
            for (src.storageChanges, dst.storage_changes) |sc, *dsc| {
                dsc.key = sc.slot.value;
                dsc.changes = try arena.alloc(types.StorageChange, sc.slotChanges.len);
                for (sc.slotChanges, dsc.changes) |slc, *dslc| {
                    dslc.index = slc.blockAccessIndex.value;
                    dslc.value = slc.postValue.value;
                }
            }

            dst.storage_reads = try arena.alloc(u256, src.storageReads.len);
            for (src.storageReads, dst.storage_reads) |sr, *dsr| dsr.* = sr.value;

            dst.balance_changes = try arena.alloc(types.BalanceChange, src.balanceChanges.len);
            for (src.balanceChanges, dst.balance_changes) |bc, *dbc| {
                dbc.index = bc.blockAccessIndex.value;
                dbc.balance = bc.postBalance.value;
            }

            dst.nonce_changes = try arena.alloc(types.NonceChange, src.nonceChanges.len);
            for (src.nonceChanges, dst.nonce_changes) |nc, *dnc| {
                dnc.index = nc.blockAccessIndex.value;
                dnc.nonce = nc.postNonce.value;
            }

            dst.code_changes = try arena.alloc(types.CodeChange, src.codeChanges.len);
            for (src.codeChanges, dst.code_changes) |cc, *dcc| {
                dcc.index = cc.blockAccessIndex.value;
                dcc.code = cc.newCode.value;
            }
        }
        break :blk result;
    };

    const txns = if (block_entry.transactions) |ts| ts else block_entry.rlp_decoded.?.transactions.?;
    var senders = try arena.alloc(u160, txns.len);
    for (txns, 0..) |tx, i| senders[i] = tx.sender.value;

    return .{
        .block = block,
        .rlp_size = block_entry.rlp.value.len,
        .bal = bal,
        .senders = senders,
    };
}

fn runBlockchainTest(gpa: std.mem.Allocator, test_case: *const BlockchainTest, comptime chainspec: zevm.chainspec.ChainSpec) !void {
    var committed = try utils.buildCommittedState(gpa, test_case.pre);
    defer committed.deinit();

    var parent: types.Block = blk: {
        var block: types.Block = undefined;
        _ = try rlp.deserialize(types.Block, gpa, test_case.genesisRLP.value, &block);
        break :blk block;
    };

    // ancestor_chain[k] = parent_hash of the block that is k+1 levels below the current parent.
    // Invariant: ancestors[0] for the next block = prepared.block.header.parent_hash (read directly);
    //            ancestors[k] for k>=1 = ancestor_chain[k-1].
    var ancestor_chain: [255][32]u8 = undefined;
    var ancestor_chain_len: usize = 0;

    var prep_arena = std.heap.ArenaAllocator.init(gpa);
    defer prep_arena.deinit();
    const blocks_parsed = try prep_arena.allocator().alloc(anyerror!zevm.processor.PreprocessedBlock, test_case.blocks.len);
    var total_gas: u64 = 30_000_000;
    for (test_case.blocks, blocks_parsed) |block_entry, *slot| {
        slot.* = prepareBlock(prep_arena.allocator(), block_entry);
        if (slot.*) |p| total_gas += p.block.header.gas_used else |_| {}
    }
    var state = try state_mod.State.init(prep_arena.allocator(), &committed, zevm.spec.Osaka.stateCapacities(total_gas));

    for (test_case.blocks, blocks_parsed) |block_entry, parse_result| {
        var arena = std.heap.ArenaAllocator.init(gpa);
        defer arena.deinit();

        const validate_err: ?anyerror, const prepared: ?zevm.processor.PreprocessedBlock = blk: {
            const p = parse_result catch |e| break :blk .{ e, null };
            var ancestors = [_]u256{0} ** 256;
            ancestors[0] = std.mem.readInt(u256, &p.block.header.parent_hash, .big);
            for (0..@min(ancestor_chain_len, 255)) |k| {
                ancestors[k + 1] = std.mem.readInt(u256, &ancestor_chain[k], .big);
            }

            if (p.bal) |bal| {
                const computed = try utils.computeBalHash(arena.allocator(), bal);
                if (p.block.header.block_access_list_hash) |expected| {
                    if (!std.mem.eql(u8, &computed, &expected)) {
                        break :blk .{ error.MismatchedBalHash, p };
                    }
                }
            }

            const proc_err: ?anyerror = if (zevm.processor.processBlock(
                arena.allocator(),
                chainspec,
                &p,
                &parent.header,
                ancestors,
                &state,
            )) |_| null else |err| err;

            if (proc_err) |_| {
                break :blk .{ proc_err, p };
            }

            const actual_root = try utils.computeStateRoot(arena.allocator(), &state, &committed);
            if (!std.mem.eql(u8, &actual_root, &p.block.header.state_root)) {
                break :blk .{ error.StateRootHashMismatch, p };
            }

            try utils.finalizeBlock(&state, &committed);

            break :blk .{ null, p };
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

fn fileWorker(io: std.Io, allocator: std.mem.Allocator, dir: std.Io.Dir, path: []const u8, fork: []const u8, any_failed: *std.atomic.Value(bool)) void {
    runBlockchainTestFile(io, allocator, dir, path, fork) catch {
        any_failed.store(true, .release);
    };
}

fn runBlockchainTestFile(io: std.Io, allocator: std.mem.Allocator, dir: std.Io.Dir, path: []const u8, fork: []const u8) !void {
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

    const fork_enum = utils.forkFromString(fork);
    var any_failed = false;
    for (parsed.value.map.keys(), parsed.value.map.values()) |name, test_case| {
        if (!std.mem.eql(u8, test_case.network, fork)) {
            continue;
        }

        switch (fork_enum) {
            inline else => |f| {
                runBlockchainTest(allocator, &test_case, zevm.chainspec.chainSpecByFork(f)) catch |err| {
                    std.debug.print("{s}: FAIL: {}\n", .{ name, err });
                    any_failed = true;
                };
            },
        }
    }
    if (any_failed) return error.BlockchainTestFailed;
}

test "blockchain tests" {
    var gpa = std.heap.DebugAllocator(.{ .thread_safe = true }){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    const io = std.testing.io;

    const fork = std.mem.span(std.c.getenv("FORK").?);
    if (std.c.getenv("BLOCKCHAIN_TEST")) |cpath| {
        try runBlockchainTestFile(io, allocator, std.Io.Dir.cwd(), std.mem.span(cpath), fork);
        return;
    }

    var lowercase_fork: [64]u8 = undefined;
    var fixtures_path: [128]u8 = undefined;
    var dir = try std.Io.Dir.cwd().openDir(
        io,
        try std.fmt.bufPrint(&fixtures_path, "fixtures/blockchain_tests/for_{s}", .{
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

    if (any_failed.load(.acquire)) return error.BlockchainTestFailed;
}
