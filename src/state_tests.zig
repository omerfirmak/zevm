const std = @import("std");
const evm = @import("evm.zig");
const state_mod = @import("state.zig");
const Bytecode = @import("bytecode.zig").Bytecode;
const ops = @import("ops.zig");
const spec = @import("spec.zig");

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

pub const Transaction = struct {
    nonce: HexInt(u64),
    gasPrice: ?HexInt(u256) = null,
    gasLimit: []HexInt(u64),
    to: ?HexInt(u160) = null,
    value: []HexInt(u256),
    data: []HexBytes,
    sender: HexInt(u160),
    secretKey: ?HexBytes = null,
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

test "state tests" {
    const supported_forks = [_][]const u8{"Osaka"};

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    if (std.posix.getenv("STATE_TEST")) |path| {
        try runStateTestFile(allocator, std.fs.cwd(), path, supported_forks[0..]);
        return;
    }

    var dir = try std.fs.cwd().openDir("fixtures/state_tests", .{ .iterate = true });
    defer dir.close();

    var walker = try dir.walk(allocator);
    defer walker.deinit();

    var any_failed = false;
    while (try walker.next()) |entry| {
        if (entry.kind != .file) continue;
        if (!std.mem.endsWith(u8, entry.path, ".json")) continue;

        runStateTestFile(allocator, dir, entry.path, supported_forks[0..]) catch |err| switch (err) {
            error.StateTestFailed => any_failed = true,
            else => return err,
        };
    }
    if (any_failed) return error.StateTestFailed;
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

            std.debug.print("{s}/{s}: ", .{ name, fork });
            runStateTest(allocator, &test_case, fork) catch |err| {
                std.debug.print("FAIL: {}\n", .{err});
                any_failed = true;
                continue;
            };
            std.debug.print("PASS\n", .{});
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
    const allocator = fba.allocator();
    const tx = test_case.transaction;
    const jump_table = ops.Ops(spec.Osaka).table();

    const post_entries = test_case.post.map.get(fork).?;

    const context = evm.Context{
        .number = test_case.env.currentNumber.value,
        .coinbase = test_case.env.currentCoinbase.value,
        .time = test_case.env.currentTimestamp.value,
        .random = if (test_case.env.currentRandom) |r| r.value else 0,
        .gas_limit = test_case.env.currentGasLimit.value,
        .basefee = test_case.env.currentBaseFee.?.value,
        .from = tx.sender.value,
        .gas_price = if (tx.gasPrice) |gp| gp.value else 0,
    };
    var vm = try evm.EVM.init(allocator, &context);

    for (post_entries) |post_entry| {
        // Build fresh state from pre for each post entry
        var state = try state_mod.State.init(allocator);
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
                state.code_storage.putAssumeCapacity(code_hash, try Bytecode.init(allocator, pre_acct.code.value, jump_table));
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

        const tx_err: ?anyerror = if (tx.to) |to|
            if (vm.process(.{
                .caller = tx.sender.value,
                .nonce = tx.nonce.value,
                .target = to.value,
                .gas_limit = @intCast(gas_limit),
                .gas_price = if (tx.gasPrice) |gp| gp.value else 0,
                .calldata = calldata,
                .value = value,
            }, &state)) |_| null else |err| err
        else
            error.ContractCreationNotImplementedYet;

        if (post_entry.expectException) |expected| {
            const actual = tx_err orelse return error.ExpectedExceptionButSucceeded;
            if (!exceptionMatches(actual, expected)) return actual;
            continue;
        } else if (tx_err) |err| {
            return err;
        }

        // Verify post state
        var failed = false;
        for (post_entry.state.map.keys(), post_entry.state.map.values()) |addr_str, expected| {
            const addr = try parseHex(u160, addr_str);
            const actual = state.accounts.read(addr);

            if (actual.nonce != expected.nonce.value) {
                failed = true;
            }
            if (actual.balance != expected.balance.value) {
                failed = true;
            }
            for (expected.storage.map.keys(), expected.storage.map.values()) |slot_str, slot_val| {
                const slot = try parseHex(u256, slot_str);
                const actual_slot = state.contract_state.read(.{ .address = @as(u256, addr), .slot = slot });
                if (actual_slot != slot_val.value) {
                    failed = true;
                }
            }
        }
        if (failed) return error.StateTestFailed;
    }
}
