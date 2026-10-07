const std = @import("std");
const RpcServer = @import("jsonrpc.zig").Server;
const Blockchain = @import("../node/blockchain.zig").Blockchain;
const Downloader = @import("../node/downloader.zig").Downloader;

pub const Eth = struct {
    const Self = @This();

    bc: *Blockchain,
    downloader: *Downloader,

    pub fn init(bc: *Blockchain, downloader: *Downloader) Self {
        return .{ .bc = bc, .downloader = downloader };
    }

    pub fn register(self: *Self, allocator: std.mem.Allocator, server: *RpcServer) !void {
        try server.register(allocator, "eth_blockNumber", @ptrCast(self), Eth.blockNumber);
        try server.register(allocator, "eth_chainId", @ptrCast(self), Eth.chainId);
        try server.register(allocator, "eth_syncing", @ptrCast(self), Eth.syncing);
    }

    pub fn blockNumber(self: *Self, _: std.Io, _: std.mem.Allocator) !HexNumber(u64) {
        return .init((try self.bc.head()).number);
    }

    pub fn chainId(self: *Self, _: std.Io, _: std.mem.Allocator) !HexNumber(u64) {
        return .init(self.bc.chainId());
    }

    pub fn syncing(self: *Self, _: std.Io, _: std.mem.Allocator) !Syncing {
        const target = self.downloader.syncTarget();
        const head = try self.bc.head();
        if (target.number <= head.number) return .not_syncing;

        return .{ .syncing = .{
            .startingBlock = .init(target.cutoff_number),
            .currentBlock = .init(head.number),
            .highestBlock = .init(target.number),
        } };
    }
};

pub const Syncing = union(enum) {
    not_syncing,
    syncing: struct {
        startingBlock: HexNumber(u64),
        currentBlock: HexNumber(u64),
        highestBlock: HexNumber(u64),
    },

    pub fn jsonStringify(self: *const Syncing, jws: anytype) !void {
        switch (self.*) {
            .not_syncing => try jws.write(false),
            .syncing => |progress| try jws.write(progress),
        }
    }
};

pub fn HexNumber(comptime T: type) type {
    comptime std.debug.assert(@typeInfo(T) == .int and @typeInfo(T).int.signedness == .unsigned);
    return struct {
        const Self = @This();
        number: T,

        pub fn init(number: T) Self {
            return .{ .number = number };
        }

        pub fn jsonParse(
            allocator: std.mem.Allocator,
            source: anytype,
            options: std.json.ParseOptions,
        ) !Self {
            _ = allocator;
            _ = options;
            switch (try source.next()) {
                .string => |text| {
                    if (text.len < 3 or text[0] != '0' or (text[1] != 'x' and text[1] != 'X')) return error.InvalidNumber;
                    return .{ .number = try std.fmt.parseUnsigned(T, text[2..], 16) };
                },
                else => return error.UnexpectedToken,
            }
        }

        pub fn jsonStringify(
            self: *const Self,
            jws: anytype,
        ) !void {
            try jws.print("\"0x{x}\"", .{self.number});
        }
    };
}
