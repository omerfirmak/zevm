// Copyright (c) 2025-2026 zevm authors
// SPDX-License-Identifier: MIT OR Apache-2.0

const std = @import("std");
const zevm = @import("zevm");
const types = zevm.types;
const utils = @import("utils.zig");

// Valid transactions carry hash and sender, invalid ones an exception.
const Result = struct {
    intrinsicGas: utils.HexInt(u64),
    exception: ?[]const u8 = null,
    hash: ?utils.HexBytes = null,
    sender: ?utils.HexInt(u160) = null,
};

const TransactionTest = struct {
    txbytes: utils.HexBytes,
    result: std.json.ArrayHashMap(Result),
};

const TransactionTestFile = std.json.ArrayHashMap(TransactionTest);

fn validateTransaction(arena: std.mem.Allocator, tx_bytes: []const u8, comptime spec: zevm.processor.Spec) !u160 {
    if (tx_bytes.len == 0) return error.EOF;
    var tx: types.Transaction = undefined;
    const consumed = try tx.decodeFromRLP(arena, tx_bytes);
    // typed transactions report the payload size, without the type byte
    const envelope_len: usize = if (tx_bytes[0] < 0x80) 1 else 0;
    if (consumed + envelope_len != tx_bytes.len) return error.InvalidSerializedLength;
    return zevm.processor.recoverTxSender(arena, &tx, spec.chain_id);
}

fn runTransactionTest(gpa: std.mem.Allocator, test_case: *const TransactionTest, fork: []const u8, comptime spec: zevm.processor.Spec) !void {
    const expected = test_case.result.map.get(fork) orelse return;

    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();

    const sender = validateTransaction(arena.allocator(), test_case.txbytes.value, spec);
    if (expected.exception) |exception| {
        const err = if (sender) |_| return error.ExpectedExceptionButSucceeded else |e| e;
        if (!utils.exceptionMatches(err, exception)) {
            std.debug.print("expected {s}, got {}\n", .{ exception, err });
            return err;
        }
        return;
    }

    if ((try sender) != expected.sender.?.value) return error.SenderMismatch;
    var hash: [32]u8 = undefined;
    std.crypto.hash.sha3.Keccak256.hash(test_case.txbytes.value, &hash, .{});
    if (!std.mem.eql(u8, &hash, expected.hash.?.value)) return error.HashMismatch;
}

fn fileWorker(io: std.Io, allocator: std.mem.Allocator, dir: std.Io.Dir, path: []const u8, fork: []const u8, any_failed: *std.atomic.Value(bool)) void {
    runTransactionTestFile(io, allocator, dir, path, fork) catch {
        any_failed.store(true, .release);
    };
}

fn runTransactionTestFile(io: std.Io, allocator: std.mem.Allocator, dir: std.Io.Dir, path: []const u8, fork: []const u8) !void {
    const file = try dir.openFile(io, path, .{});
    defer file.close(io);

    var buf: [1024]u8 = undefined;
    var reader = file.reader(io, &buf);
    const contents = try reader.interface.allocRemaining(allocator, .unlimited);
    defer allocator.free(contents);

    const parsed = std.json.parseFromSlice(TransactionTestFile, allocator, contents, .{
        .ignore_unknown_fields = true,
    }) catch |e| {
        std.debug.print("failed to parse {s}\n", .{path});
        return e;
    };
    defer parsed.deinit();

    const fork_enum = utils.forkFromString(fork);
    var any_failed = false;
    for (parsed.value.map.keys(), parsed.value.map.values()) |name, test_case| {
        switch (fork_enum) {
            inline .Osaka, .BPO1, .BPO2, .Amsterdam => |f| {
                runTransactionTest(allocator, &test_case, fork, zevm.processor.Spec.fromFork(f, 1)) catch |err| {
                    std.debug.print("{s}: FAIL: {}\n", .{ name, err });
                    any_failed = true;
                };
            },
            else => unreachable,
        }
    }
    if (any_failed) return error.TransactionTestFailed;
}

test "transaction tests" {
    var gpa = std.heap.DebugAllocator(.{ .thread_safe = true }){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    const io = std.testing.io;

    const fork = std.mem.span(std.c.getenv("FORK").?);
    if (std.c.getenv("TRANSACTION_TEST")) |cpath| {
        try runTransactionTestFile(io, allocator, std.Io.Dir.cwd(), std.mem.span(cpath), fork);
        return;
    }

    var lowercase_fork: [64]u8 = undefined;
    var fixtures_path: [128]u8 = undefined;
    var dir = try std.Io.Dir.cwd().openDir(
        io,
        try std.fmt.bufPrint(&fixtures_path, "fixtures/transaction_tests/for_{s}", .{
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

    if (any_failed.load(.acquire)) return error.TransactionTestFailed;
}
