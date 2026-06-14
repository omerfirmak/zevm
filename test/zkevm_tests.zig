const std = @import("std");
const guest = @import("guest");
const utils = @import("utils.zig");

// Only the two fields we care about per block — everything else is ignored at parse time.
// Fields are optional: "expected invalid" sibling blocks in multi-test fixtures lack these
// (they only carry `rlp` + `blockHeader`), so we skip those blocks rather than failing to parse.
const BlockEntry = struct {
    statelessInputBytes: ?utils.HexBytes = null,
    statelessOutputBytes: ?utils.HexBytes = null,
};

const ZkTest = struct {
    network: []const u8,
    blocks: []BlockEntry,
};

const ZkTestFile = std.json.ArrayHashMap(ZkTest);

fn runZkTest(io: std.Io, allocator: std.mem.Allocator, test_case: *const ZkTest) !void {
    const use_ziskemu = std.c.getenv("ZISKEMU_GUEST") != null;

    for (test_case.blocks) |block| {
        var arena = std.heap.ArenaAllocator.init(allocator);
        defer arena.deinit();

        const input = block.statelessInputBytes orelse continue;
        const output = block.statelessOutputBytes orelse continue;
        const expected = output.value;

        const got: []const u8 = if (use_ziskemu)
            try runInZiskemu(io, arena.allocator(), "zig-out/bin/zevm-zisk-guest", input.value)
        else
            try guest.verify_ssz(arena.allocator(), input.value);

        if (got.len < expected.len or !std.mem.eql(u8, got[0..expected.len], expected)) {
            return error.OutputMismatch;
        }
    }
}

var tmp_counter: std.atomic.Value(u64) = .init(0);

fn runInZiskemu(io: std.Io, allocator: std.mem.Allocator, guest_path: []const u8, payload: []const u8) ![]u8 {
    const pid = std.c.getpid();
    const seq = tmp_counter.fetchAdd(1, .monotonic);
    const in_path = try std.fmt.allocPrint(allocator, "/tmp/ziskemu_in_{d}_{d}.bin", .{ pid, seq });
    const out_path = try std.fmt.allocPrint(allocator, "/tmp/ziskemu_out_{d}_{d}.bin", .{ pid, seq });
    const cwd = std.Io.Dir.cwd();
    defer cwd.deleteFile(io, in_path) catch {};
    defer cwd.deleteFile(io, out_path) catch {};

    {
        const f = try cwd.createFile(io, in_path, .{});
        defer f.close(io);
        var len_buf: [8]u8 = undefined;
        std.mem.writeInt(u64, &len_buf, payload.len, .little);
        try f.writeStreamingAll(io, &len_buf);
        try f.writeStreamingAll(io, payload);
        const need_pad = (8 - ((8 + payload.len) % 8)) % 8;
        if (need_pad != 0) {
            const zeros = [_]u8{0} ** 7;
            try f.writeStreamingAll(io, zeros[0..need_pad]);
        }
    }

    var child = try std.process.spawn(io, .{
        .argv = &.{ "ziskemu", "-e", guest_path, "-i", in_path, "-o", out_path },
        .stdin = .ignore,
        .stdout = .ignore,
        .stderr = .inherit,
    });
    const term = try child.wait(io);
    if (term != .exited or term.exited != 0) {
        return error.ZiskemuFailed;
    }

    return cwd.readFileAlloc(io, out_path, allocator, .unlimited);
}

fn fileWorker(io: std.Io, allocator: std.mem.Allocator, dir: std.Io.Dir, path: []const u8, fork: []const u8, any_failed: *std.atomic.Value(bool)) void {
    runZkTestFile(io, allocator, dir, path, fork) catch {
        any_failed.store(true, .release);
    };
}

fn runZkTestFile(io: std.Io, allocator: std.mem.Allocator, dir: std.Io.Dir, path: []const u8, fork: []const u8) !void {
    const file = try dir.openFile(io, path, .{});
    defer file.close(io);

    var buf: [1024]u8 = undefined;
    var reader = file.reader(io, &buf);
    const contents = try reader.interface.allocRemaining(allocator, .unlimited);
    defer allocator.free(contents);

    const parsed = std.json.parseFromSlice(ZkTestFile, allocator, contents, .{
        .ignore_unknown_fields = true,
    }) catch |e| {
        std.debug.print("failed to parse {s}\n", .{path});
        return e;
    };
    defer parsed.deinit();

    var any_failed = false;
    for (parsed.value.map.keys(), parsed.value.map.values()) |name, test_case| {
        if (!std.mem.eql(u8, test_case.network, fork)) continue;
        runZkTest(io, allocator, &test_case) catch |err| {
            std.debug.print("{s}: FAIL: {}\n", .{ name, err });
            any_failed = true;
        };
    }
    if (any_failed) return error.ZkTestFailed;
}

test "zkevm tests" {
    var gpa = std.heap.DebugAllocator(.{ .thread_safe = true }){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    const io = std.testing.io;

    const fork = std.mem.span(std.c.getenv("FORK").?);
    if (std.c.getenv("ZK_TEST")) |cpath| {
        try runZkTestFile(io, allocator, std.Io.Dir.cwd(), std.mem.span(cpath), fork);
        return;
    }

    var lowercase_fork: [64]u8 = undefined;
    var fixtures_path: [128]u8 = undefined;
    var dir = try std.Io.Dir.cwd().openDir(
        io,
        try std.fmt.bufPrint(&fixtures_path, "zk_fixtures/blockchain_tests/for_{s}", .{
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

    if (any_failed.load(.acquire)) return error.ZkTestFailed;
}
