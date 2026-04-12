const std = @import("std");
const clap = @import("clap");
const evm = @import("evm.zig");
const types = @import("types.zig");
const state_mod = @import("state.zig");
const spec = @import("spec.zig");

const BenchmarkDef = struct {
    name: []const u8,
    /// Hex-encoded bytecode (as produced by @embedFile on a .hex file).
    hex_bytes: []const u8,
    /// Raw calldata bytes.
    calldata: []const u8,
    gas_limit: i32 = 1_000_000_000,
    /// Size of the deployed-bytecode buffer (bytes).
    bytecode_buf_size: usize = 4 * 1024 * 1024,
};

// Fork with elevated max_tx_gas to accommodate heavy benchmarks,
// matching revm's `tx_gas_limit_cap = Some(u64::MAX)` config.
const bench_fork = blk: {
    var f = spec.Osaka;
    f.max_tx_gas = std.math.maxInt(i32);
    break :blk f;
};

// Use non-precompile addresses (Ethereum precompiles occupy 0x01-0x0a).
const BENCH_CALLER: u160 = 0x1000000000000000000000000000000000000000;
const BENCH_TARGET: u160 = 0x1000000000000000000000000000000000000001;

const params = clap.parseParamsComptime(
    \\-h, --help               Display this help and exit.
    \\-B, --bytecode <str>     Path to hex bytecode file
    \\-c, --calldata <str>     Calldata as a hex string
    \\-g, --gas-limit <usize>  Gas limit
    \\-w, --warmup <usize>     Warmup iterations (default: 10).
    \\-i, --iters <usize>      Benchmark iterations (default: 100).
    \\
);

pub fn main() !void {
    @import("precompile.zig").init();

    var gpa_state = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa_state.deinit();
    const allocator = gpa_state.allocator();

    var diag = clap.Diagnostic{};
    var res = clap.parse(clap.Help, &params, clap.parsers.default, .{
        .diagnostic = &diag,
        .allocator = allocator,
    }) catch |err| {
        try diag.reportToFile(std.fs.File.stderr(), err);
        return err;
    };
    defer res.deinit();

    if (res.args.help != 0)
        return clap.helpToFile(std.fs.File.stderr(), clap.Help, &params, .{});

    const warmup = res.args.warmup orelse 10;
    const iters = res.args.iters orelse 100;

    const hex_bytes = try std.fs.cwd().readFileAlloc(allocator, res.args.bytecode.?, 10 * 1024 * 1024);
    defer allocator.free(hex_bytes);

    const calldata: []u8 = if (res.args.calldata) |cd_hex|
        try decodeHex(allocator, cd_hex)
    else
        &.{};
    defer if (res.args.calldata != null) allocator.free(calldata);

    const bench_def: BenchmarkDef = .{
        .name = std.fs.path.basename(res.args.bytecode.?),
        .hex_bytes = hex_bytes,
        .calldata = calldata,
        .gas_limit = if (res.args.@"gas-limit") |gl| @intCast(gl) else 1_000_000_000,
    };
    return runBenchmark(allocator, bench_def, warmup, iters);
}

fn runBenchmark(allocator: std.mem.Allocator, bench_def: BenchmarkDef, warmup: usize, iters: usize) !void {
    const bytecode = try decodeHex(allocator, bench_def.hex_bytes);
    defer allocator.free(bytecode);

    var state = try state_mod.State.init(allocator, bench_def.bytecode_buf_size);
    defer state.deinit(allocator);

    _ = state.accounts.write(BENCH_CALLER, .{
        .nonce = 0,
        .balance = std.math.maxInt(u256),
        .code_hash = types.empty_code_hash,
        .storage_hash = types.empty_root_hash,
    });

    var code_hash_bytes: [32]u8 = undefined;
    std.crypto.hash.sha3.Keccak256.hash(bytecode, &code_hash_bytes, .{});
    const code_hash = std.mem.readInt(u256, &code_hash_bytes, .big);
    state.deploy_code(code_hash, bytecode, bench_fork);

    _ = state.accounts.write(BENCH_TARGET, .{
        .nonce = 1,
        .balance = 0,
        .code_hash = code_hash,
        .storage_hash = types.empty_root_hash,
    });

    const context = evm.Context{
        .chainid = 1,
        .number = 1,
        .coinbase = 0,
        .time = 0,
        .random = 0,
        .basefee = 0,
        .gas_limit = @intCast(bench_def.gas_limit),
        .excess_blob_gas = 0,
        .max_blobs_per_block = 9,
        .blob_base_fee_update_fraction = 5_000_000,
    };

    const calldata_buf = try allocator.dupe(u8, bench_def.calldata);
    defer allocator.free(calldata_buf);

    var msg = evm.Message{
        .caller = BENCH_CALLER,
        .nonce = 0,
        .target = BENCH_TARGET,
        .gas_limit = bench_def.gas_limit,
        .gas_price = 0,
        .calldata = calldata_buf,
        .value = 0,
    };

    const initial_snapshot = state.snapshot();

    var vm_arena = std.heap.ArenaAllocator.init(allocator);
    defer vm_arena.deinit();

    std.debug.print("{s}  warmup={d}  iters={d}\n", .{ bench_def.name, warmup, iters });

    // Benchmark — vm.process
    var times = try allocator.alloc(u64, iters);
    defer allocator.free(times);
    var timer = try std.time.Timer.start();
    var gas_used: i32 = 0;

    for (0..iters + warmup) |i| {
        _ = vm_arena.reset(.retain_capacity);
        var logs: std.DoublyLinkedList = .{};

        var vm = try evm.EVM.init(vm_arena.allocator(), vm_arena.allocator(), &logs, &msg, &context);
        timer.reset();
        gas_used = vm.process(bench_fork, &state) catch |err| {
            std.debug.print("error at iter {d}: {}\n", .{ i, err });
            return;
        };
        if (i >= warmup) {
            times[i - warmup] = timer.read();
        }
        std.mem.doNotOptimizeAway(&vm);

        state.revert(initial_snapshot);
        msg.nonce = 0;
    }

    std.mem.sort(u64, times, {}, std.sort.asc(u64));
    const total: u64 = blk: {
        var s: u64 = 0;
        for (times) |t| s += t;
        break :blk s;
    };
    const mean_ns = total / iters;
    const median_ns = times[iters / 2];
    const min_ns = times[0];
    const max_ns = times[iters - 1];

    std.debug.print("  min    {d:.3} ms\n", .{nsToMs(min_ns)});
    std.debug.print("  median {d:.3} ms\n", .{nsToMs(median_ns)});
    std.debug.print("  mean   {d:.3} ms\n", .{nsToMs(mean_ns)});
    std.debug.print("  max    {d:.3} ms\n", .{nsToMs(max_ns)});
    std.debug.print("  gas    {}\n", .{gas_used});
}

fn nsToMs(ns: u64) f64 {
    return @as(f64, @floatFromInt(ns)) / 1_000_000.0;
}

fn decodeHex(allocator: std.mem.Allocator, hex: []const u8) ![]u8 {
    const src = std.mem.trimRight(u8, hex, "\n\r");
    const len = src.len / 2;
    const out = try allocator.alloc(u8, len);
    for (0..len) |i| {
        out[i] = (try hexNibble(src[i * 2])) << 4 | (try hexNibble(src[i * 2 + 1]));
    }
    return out;
}

fn hexNibble(c: u8) !u8 {
    return switch (c) {
        '0'...'9' => c - '0',
        'a'...'f' => c - 'a' + 10,
        'A'...'F' => c - 'A' + 10,
        else => error.InvalidHex,
    };
}
