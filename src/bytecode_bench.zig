// Copyright (c) 2025-2026 zevm authors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Opt-in micro-benchmark for instruction boundary scanning in `Bytecode`.
//!
//! Every repetition performs what a far jump in a freshly loaded contract
//! costs: `Bytecode.init` (shared metadata plus the first page),
//! `isValidJumpDest` to a destination near the end of the code (scans every
//! byte in between and decodes the destination page), and `deinit`. A second
//! series measures `init` + `deinit` alone, so the difference attributes the
//! remaining cost to the scan and the destination page.
//!
//! Memory comes from a `FixedBufferAllocator` reset before each repetition,
//! the bump allocator `State` uses for deployed code. Code generation is
//! seeded, so every run scans identical bytes.
//!
//! Build: zig build bench-bytecode -Doptimize=ReleaseSafe
//! Run:   zig-out/bin/zevm-bytecode-bench [iters] [warmup]

const std = @import("std");
const Bytecode = @import("evm/bytecode.zig").Bytecode;
const Opcode = @import("evm/opcode.zig").Opcode;
const Config = @import("evm/config.zig").Config;
const Spec = @import("evm/spec.zig").Spec;

const amsterdam: Config = .{ .fork = Spec.fromFork(.Amsterdam) };
const osaka: Config = .{ .fork = Spec.fromFork(.Osaka) };

const default_iters = 300;
const default_warmup = 30;
const seed = 0x5eed_b0bc_0de5_0000;

const far_len = 64 * 1024;
/// Destination of the first-page jump in the 64 KiB workloads.
const far_dest = 0xffe4;
const short_len = 128;
const short_dest = 120;

/// Relative frequencies of the instruction classes a generator emits.
const Mix = struct {
    one_byte: []const Opcode,
    /// Weights for: one-byte opcode, PUSH1, PUSH2, PUSH4, PUSH20, PUSH32.
    weights: [6]u32,
    /// Fixed immediate byte, or random immediates when null.
    imm_byte: ?u8 = null,
};

const push_sizes = [_]u8{ 0, 1, 2, 4, 20, 32 };

/// Random PUSH1/JUMPDEST filler like the Plataberget contracts.
const push1_jumpdest_mix: Mix = .{
    .one_byte = &.{.JUMPDEST},
    .weights = .{ 1, 1, 0, 0, 0, 0 },
};

/// PUSH32 words whose data bytes all look like JUMPDEST, as in the unit tests.
const push32_jumpdest_mix: Mix = .{
    .one_byte = &.{.JUMPDEST},
    .weights = .{ 0, 0, 0, 0, 0, 1 },
    .imm_byte = Opcode.JUMPDEST.byte(),
};

/// Ordinary compiler output: mostly one-byte stack and memory operations,
/// frequent small pushes, occasional address and word constants.
const straight_line_mix: Mix = .{
    .one_byte = &.{
        .ADD,       .MUL,          .SUB,          .DIV,   .LT,       .GT,     .EQ,     .ISZERO,
        .AND,       .OR,           .NOT,          .SHL,   .SHR,      .POP,    .MLOAD,  .MSTORE,
        .SLOAD,     .SSTORE,       .JUMP,         .JUMPI, .JUMPDEST, .PUSH0,  .DUP1,   .DUP2,
        .DUP3,      .DUP4,         .SWAP1,        .SWAP2, .SWAP3,    .RETURN, .REVERT, .KECCAK256,
        .CALLVALUE, .CALLDATALOAD, .CALLDATASIZE,
    },
    .weights = .{ 72, 16, 7, 2, 2, 1 },
};

const Workload = struct {
    name: []const u8,
    code: []u8,
    dest: usize,
};

/// Fills `region` with whole instructions drawn from `mix`. Instructions that
/// would cross the end are replaced by JUMPDEST padding, so the position right
/// after `region` is always an instruction boundary.
fn fillInstructions(region: []u8, random: std.Random, mix: Mix) void {
    var pc: usize = 0;
    while (pc < region.len) {
        const class = random.weightedIndex(u32, &mix.weights);
        if (class == 0) {
            region[pc] = mix.one_byte[random.uintLessThan(usize, mix.one_byte.len)].byte();
            pc += 1;
            continue;
        }
        const size = push_sizes[class];
        if (pc + 1 + size > region.len) {
            @memset(region[pc..], Opcode.JUMPDEST.byte());
            return;
        }
        region[pc] = Opcode.PUSH1.byte() + size - 1;
        const imm = region[pc + 1 .. pc + 1 + size];
        if (mix.imm_byte) |byte| @memset(imm, byte) else random.bytes(imm);
        pc += 1 + size;
    }
}

/// Builds a contract that jumps from its first instruction to `dest`, with
/// `mix` filler in between and a `JUMPDEST STOP` routine at `dest`.
fn buildWorkload(allocator: std.mem.Allocator, name: []const u8, len: usize, dest: usize, mix: Mix) !Workload {
    const code = try allocator.alloc(u8, len);
    var prng = std.Random.DefaultPrng.init(seed);
    const header: []const u8 = if (dest > 0xff)
        &.{ Opcode.PUSH2.byte(), @intCast(dest >> 8), @truncate(dest), Opcode.JUMP.byte() }
    else
        &.{ Opcode.PUSH1.byte(), @intCast(dest), Opcode.JUMP.byte() };
    @memcpy(code[0..header.len], header);
    fillInstructions(code[header.len..dest], prng.random(), mix);
    @memset(code[dest..], Opcode.STOP.byte());
    code[dest] = Opcode.JUMPDEST.byte();
    return .{ .name = name, .code = code, .dest = dest };
}

const Series = enum { init_only, init_jump };

/// Times `samples.len` repetitions of init (+ far jump) + deinit.
fn measure(
    io: std.Io,
    fba: *std.heap.FixedBufferAllocator,
    workload: Workload,
    comptime cfg: Config,
    comptime series: Series,
    samples: []u64,
) !void {
    const allocator = fba.allocator();
    for (samples) |*sample| {
        fba.reset();
        const start = std.Io.Timestamp.now(io, .awake);
        var bytecode = try Bytecode.init(allocator, workload.code, cfg);
        if (series == .init_jump) {
            const ip = (try bytecode.isValidJumpDest(workload.dest, cfg)) orelse return error.InvalidJumpDest;
            std.mem.doNotOptimizeAway(ip);
        }
        bytecode.deinit(allocator);
        sample.* = @intCast(start.durationTo(std.Io.Timestamp.now(io, .awake)).toNanoseconds());
    }
}

const Stats = struct {
    min: u64,
    median: u64,
    p90: u64,

    fn of(samples: []u64) Stats {
        std.mem.sort(u64, samples, {}, std.sort.asc(u64));
        return .{ .min = samples[0], .median = samples[samples.len / 2], .p90 = samples[samples.len * 9 / 10] };
    }
};

fn runFork(io: std.Io, gpa: std.mem.Allocator, workloads: []const Workload, comptime cfg: Config, iters: usize, warmup: usize) !void {
    const buffer = try gpa.alloc(u8, 1 << 20);
    defer gpa.free(buffer);
    var fba = std.heap.FixedBufferAllocator.init(buffer);
    const samples = try gpa.alloc(u64, iters + warmup);
    defer gpa.free(samples);

    std.debug.print("fork={s}\n", .{@tagName(cfg.fork.fork)});
    std.debug.print("{s:<20} {s:>7} {s:>14} {s:>14} {s:>14} {s:>14} {s:>10}\n", .{
        "workload", "bytes", "init+deinit", "init+jump", "jump min", "jump p90", "scan ns/B",
    });
    for (workloads) |workload| {
        try measure(io, &fba, workload, cfg, .init_only, samples);
        const base = Stats.of(samples[warmup..]);
        try measure(io, &fba, workload, cfg, .init_jump, samples);
        const full = Stats.of(samples[warmup..]);
        const scan_ns = full.median -| base.median;
        const scanned: f64 = @floatFromInt(workload.dest);
        std.debug.print("{s:<20} {d:>7} {d:>11} ns {d:>11} ns {d:>11} ns {d:>11} ns {d:>10.3}\n", .{
            workload.name, workload.code.len, base.median,                                full.median,
            full.min,      full.p90,          @as(f64, @floatFromInt(scan_ns)) / scanned,
        });
    }
}

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    var args = init.minimal.args.iterate();
    _ = args.skip();
    const iters = if (args.next()) |arg| try std.fmt.parseInt(usize, arg, 10) else default_iters;
    const warmup = if (args.next()) |arg| try std.fmt.parseInt(usize, arg, 10) else default_warmup;
    if (iters == 0) return error.NoIterations;

    const workloads = [_]Workload{
        try buildWorkload(gpa, "push1_jumpdest_64k", far_len, far_dest, push1_jumpdest_mix),
        try buildWorkload(gpa, "push32_jumpdest_64k", far_len, far_dest, push32_jumpdest_mix),
        try buildWorkload(gpa, "straight_line_64k", far_len, far_dest, straight_line_mix),
        try buildWorkload(gpa, "straight_line_short", short_len, short_dest, straight_line_mix),
    };
    defer for (workloads) |workload| gpa.free(workload.code);

    std.debug.print("bytecode boundary scan: iters={d} warmup={d} (median unless noted; scan ns/B = (init+jump - init+deinit) / dest)\n", .{ iters, warmup });
    try runFork(init.io, gpa, &workloads, amsterdam, iters, warmup);
    try runFork(init.io, gpa, &workloads, osaka, iters, warmup);
}
