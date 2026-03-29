const std = @import("std");
const evm = @import("evm.zig");
const state_mod = @import("state.zig");
const Bytecode = @import("bytecode.zig").Bytecode;
const ops = @import("ops.zig");
const spec = @import("spec.zig");
const RoundedAllocator = @import("rounded_alloc.zig").RoundedAllocator;

fn parseHex(comptime T: type, str: []const u8) !T {
    const hex = if (std.mem.startsWith(u8, str, "0x")) str[2..] else str;
    if (hex.len == 0) return 0;
    return std.fmt.parseInt(T, hex, 16);
}

pub fn HexInt(comptime Int: type) type {
    return struct {
        value: Int,

        pub fn jsonParse(allocator: std.mem.Allocator, source: anytype, options: std.json.ParseOptions) !@This() {
            const str = try std.json.innerParse([]const u8, allocator, source, options);
            const hex = if (std.mem.startsWith(u8, str, "0x")) str[2..] else str;
            const value = if (hex.len == 0) 0 else try std.fmt.parseInt(Int, hex, 16);
            return .{ .value = value };
        }
    };
}

pub const HexBytes = struct {
    value: []u8,

    pub fn jsonParse(allocator: std.mem.Allocator, source: anytype, options: std.json.ParseOptions) !@This() {
        const str = try std.json.innerParse([]const u8, allocator, source, options);
        const hex = if (std.mem.startsWith(u8, str, "0x")) str[2..] else str;
        if (hex.len == 0) return .{ .value = &.{} };
        const bytes = try allocator.alloc(u8, hex.len / 2);
        _ = std.fmt.hexToBytes(bytes, hex) catch return error.InvalidCharacter;
        return .{ .value = bytes };
    }
};

pub const AccountState = struct {
    nonce: HexInt(u64),
    balance: HexInt(u256),
    code: HexBytes,
    storage: std.json.ArrayHashMap(HexInt(u256)),
};

pub const Env = struct {
    currentCoinbase: HexInt(u160),
    currentGasLimit: HexInt(u64),
    currentNumber: HexInt(u64),
    currentTimestamp: HexInt(u64),
    currentRandom: ?HexInt(u256) = null,
    currentDifficulty: HexInt(u256),
    currentBaseFee: ?HexInt(u256) = null,
    currentExcessBlobGas: ?HexInt(u64) = null,
};

pub const AccessListEntry = struct {
    address: HexInt(u160),
    storageKeys: []HexInt(u256),
};

pub const Transaction = struct {
    nonce: HexInt(u64),
    gasPrice: ?HexInt(u256) = null,
    // EIP-1559 (type 2) fee fields
    maxFeePerGas: ?HexInt(u256) = null,
    maxPriorityFeePerGas: ?HexInt(u256) = null,
    gasLimit: []HexInt(u64),
    to: ?HexInt(u160) = null,
    value: []HexInt(u256),
    data: []HexBytes,
    sender: HexInt(u160),
    secretKey: ?HexBytes = null,
    // EIP-2930: one access list per data index (parallel to data[]/gasLimit[]/value[])
    accessLists: ?[][]AccessListEntry = null,
};

pub const PostIndexes = struct {
    data: u32,
    gas: u32,
    value: u32,
};

pub const PostEntry = struct {
    hash: HexBytes,
    logs: HexBytes,
    txbytes: HexBytes,
    indexes: PostIndexes,
    state: std.json.ArrayHashMap(AccountState),
    expectException: ?[]const u8 = null,
};

pub const BlobScheduleEntry = struct {
    target: HexInt(u64),
    max: HexInt(u64),
    baseFeeUpdateFraction: HexInt(u64),
};

pub const Config = struct {
    blobSchedule: ?std.json.ArrayHashMap(BlobScheduleEntry) = null,
    chainid: HexInt(u64),
};

pub const Info = struct {
    hash: HexBytes,
    comment: []const u8,
    @"filling-transition-tool": []const u8,
    description: []const u8,
    url: []const u8,
    @"fixture-format": []const u8,
    @"reference-spec": ?[]const u8 = null,
    @"reference-spec-version": ?[]const u8 = null,
};

pub const StateTest = struct {
    env: Env,
    pre: std.json.ArrayHashMap(AccountState),
    transaction: Transaction,
    post: std.json.ArrayHashMap([]PostEntry),
    config: Config,
    _info: Info,
};

// Top-level JSON is a map of test name -> StateTest
pub const StateTestFile = std.json.ArrayHashMap(StateTest);

var print_mutex: std.Thread.Mutex = .{};

test "state tests" {
    const supported_forks = [_][]const u8{"Osaka"};

    var gpa = std.heap.GeneralPurposeAllocator(.{ .thread_safe = true }){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    if (std.posix.getenv("STATE_TEST")) |path| {
        try runStateTestFile(allocator, std.fs.cwd(), path, supported_forks[0..]);
        return;
    }

    var dir = try std.fs.cwd().openDir("fixtures/state_tests", .{ .iterate = true });
    defer dir.close();

    var paths = std.ArrayListUnmanaged([]u8){};
    defer {
        for (paths.items) |p| allocator.free(p);
        paths.deinit(allocator);
    }
    {
        var walker = try dir.walk(allocator);
        defer walker.deinit();
        while (try walker.next()) |entry| {
            if (entry.kind != .file) continue;
            if (!std.mem.endsWith(u8, entry.path, ".json")) continue;
            try paths.append(allocator, try allocator.dupe(u8, entry.path));
        }
    }

    var any_failed = std.atomic.Value(bool).init(false);
    var pool: std.Thread.Pool = undefined;
    try pool.init(.{ .allocator = allocator });
    defer pool.deinit();
    var wg = std.Thread.WaitGroup{};
    for (paths.items) |path| {
        pool.spawnWg(&wg, fileWorker, .{ allocator, dir, path, supported_forks[0..], &any_failed });
    }
    pool.waitAndWork(&wg);

    if (any_failed.load(.acquire)) return error.StateTestFailed;
}

fn fileWorker(allocator: std.mem.Allocator, dir: std.fs.Dir, path: []const u8, forks: []const []const u8, any_failed: *std.atomic.Value(bool)) void {
    runStateTestFile(allocator, dir, path, forks) catch {
        any_failed.store(true, .release);
    };
}

fn runStateTestFile(allocator: std.mem.Allocator, dir: std.fs.Dir, path: []const u8, forks: []const []const u8) !void {
    const file = try dir.openFile(path, .{});
    defer file.close();

    const contents = try file.readToEndAlloc(allocator, 128 * 1024 * 1024);
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

            const test_err = runStateTest(allocator, &test_case, fork);
            print_mutex.lock();
            test_err catch |err| {
                std.debug.print("{s}: FAIL: {}\n", .{ name, err });
                any_failed = true;
            };
            print_mutex.unlock();
        }
    }
    if (any_failed) return error.StateTestFailed;
}

fn mapException(name: []const u8) ?anyerror {
    const map = .{
        .{ "TransactionException.INSUFFICIENT_ACCOUNT_FUNDS", evm.Errors.NotEnoughFunds },
        .{ "TransactionException.GASLIMIT_PRICE_PRODUCT_OVERFLOW", evm.Errors.GasOverflow },
        .{ "TransactionException.GAS_ALLOWANCE_EXCEEDED", evm.Errors.GasOverflow },
        .{ "TransactionException.GAS_LIMIT_EXCEEDS_MAXIMUM", evm.Errors.GasOverflow },
        .{ "TransactionException.INTRINSIC_GAS_TOO_LOW", evm.Errors.OutOfGas },
        .{ "TransactionException.INTRINSIC_GAS_BELOW_FLOOR_GAS_COST", evm.Errors.OutOfGas },
        .{ "TransactionException.NONCE_IS_MAX", evm.Errors.NonceMax },
    };
    inline for (map) |entry| {
        if (std.mem.eql(u8, name, entry[0])) return entry[1];
    }
    return null;
}

// Returns true if `err` satisfies any exception in the `|`-separated list.
fn exceptionMatches(err: anyerror, expected: []const u8) bool {
    var it = std.mem.splitScalar(u8, expected, '|');
    while (it.next()) |ex| {
        if (mapException(ex)) |mapped| {
            if (err == mapped) return true;
        }
    }
    return false;
}

fn runStateTest(gpa: std.mem.Allocator, test_case: *const StateTest, fork: []const u8) !void {
    var fba = std.heap.FixedBufferAllocator.init(try gpa.alloc(u8, 1_024_000_000));
    defer gpa.free(fba.buffer);
    var rounded = RoundedAllocator{ .backing = fba.allocator() };
    const allocator = rounded.allocator();
    const tx = test_case.transaction;
    const forkSpec = spec.Osaka;
    const jump_table = ops.Ops(forkSpec).table();

    const post_entries = test_case.post.map.get(fork).?;

    const basefee = test_case.env.currentBaseFee.?.value;
    const effective_gas_price: u256 = if (tx.maxFeePerGas) |mfpg| blk: {
        const priority: u256 = if (tx.maxPriorityFeePerGas) |mpfpg| mpfpg.value else 0;
        break :blk @min(mfpg.value, basefee + priority);
    } else if (tx.gasPrice) |gp| gp.value else 0;

    const context = evm.Context{
        .number = test_case.env.currentNumber.value,
        .coinbase = test_case.env.currentCoinbase.value,
        .time = test_case.env.currentTimestamp.value,
        .random = if (test_case.env.currentRandom) |r| r.value else 0,
        .gas_limit = test_case.env.currentGasLimit.value,
        .basefee = basefee,
        .from = tx.sender.value,
        .gas_price = effective_gas_price,
    };
    var vm = try evm.EVM.init(allocator, &context, @ptrCast(&jump_table));

    for (post_entries) |post_entry| {
        // Build fresh state from pre for each post entry
        var state = try state_mod.State.init(allocator, 10_000_000);
        defer state.deinit(allocator);

        for (test_case.pre.map.keys(), test_case.pre.map.values()) |addr_str, pre_acct| {
            const addr = try parseHex(u160, addr_str);
            for (pre_acct.storage.map.keys(), pre_acct.storage.map.values()) |slot_str, slot_val| {
                const slot = try parseHex(u256, slot_str);
                if (slot_val.value != 0) {
                    _ = state.contract_state.write(.{ .address = addr, .slot = slot }, slot_val.value);
                }
            }

            var code_hash: u256 = state_mod.empty_code_hash;
            if (pre_acct.code.value.len > 0) {
                std.crypto.hash.sha3.Keccak256.hash(pre_acct.code.value, @ptrCast(&code_hash), .{});
                state.code_storage.putAssumeCapacity(code_hash, try Bytecode.init(allocator, pre_acct.code.value, &jump_table));
            }

            _ = state.accounts.write(addr, .{
                .nonce = pre_acct.nonce.value,
                .balance = pre_acct.balance.value,
                .code_hash = code_hash,
                .storage_hash = state_mod.empty_root_hash,
            });
        }

        const gas_limit = tx.gasLimit[post_entry.indexes.gas].value;
        const value = tx.value[post_entry.indexes.value].value;
        const calldata = tx.data[post_entry.indexes.data].value;

        // convert parsed access list entries to evm.AccessListEntry for this tx variant
        const raw_al: []AccessListEntry = if (tx.accessLists) |als|
            if (post_entry.indexes.data < als.len) als[post_entry.indexes.data] else &.{}
        else
            &.{};
        const access_list = try allocator.alloc(evm.AccessListEntry, raw_al.len);
        for (raw_al, access_list) |src, *dst| {
            const keys = try allocator.alloc(u256, src.storageKeys.len);
            for (src.storageKeys, keys) |k, *out| out.* = k.value;
            dst.* = .{ .address = src.address.value, .storage_keys = keys };
        }

        const to = if (tx.to) |t| t.value else 0;
        const tx_err: ?anyerror = if (vm.process(forkSpec, .{
            .caller = tx.sender.value,
            .nonce = tx.nonce.value,
            .target = to,
            .gas_limit = @intCast(gas_limit),
            .gas_price = effective_gas_price,
            .calldata = calldata,
            .value = value,
            .access_list = access_list,
        }, &state)) |_| null else |err| err;

        if (post_entry.expectException) |expected| {
            const actual = tx_err orelse return error.ExpectedExceptionButSucceeded;
            if (!exceptionMatches(actual, expected)) return actual;
            continue;
        } else if (tx_err) |err| {
            return err;
        }

        var num_alive_accounts: usize = 0;
        // Verify no alive account in actual state is missing from post state
        var actual_it = state.accounts.dirties.keyIterator();
        while (actual_it.next()) |entry| {
            const ca_entry = vm.created_accounts.getEntry(entry.*);
            if (ca_entry == null or ca_entry.?.value_ptr.* == true) {
                num_alive_accounts += 1;
            }
        }

        if (num_alive_accounts != post_entry.state.map.keys().len) {
            return error.UnexpectedNumOfAccounts;
        }

        // Verify post state
        for (post_entry.state.map.keys(), post_entry.state.map.values()) |addr_str, expected| {
            const addr = try parseHex(u160, addr_str);
            const actual = state.accounts.read(addr);

            if (actual.nonce != expected.nonce.value) {
                return error.NonceCheckFailed;
            }
            for (expected.storage.map.keys(), expected.storage.map.values()) |slot_str, slot_val| {
                const slot = try parseHex(u256, slot_str);
                const actual_slot = state.contract_state.read(.{ .address = @as(u256, addr), .slot = slot });
                if (actual_slot != slot_val.value) {
                    return error.StorageCheckFailed;
                }
            }
            if (actual.balance != expected.balance.value) {
                return error.BalanceCheckFailed;
            }
        }
    }
}
