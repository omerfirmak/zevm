const std = @import("std");
const RpcServer = @import("jsonrpc.zig").Server;
const Blockchain = @import("../node/blockchain.zig").Blockchain;
const Downloader = @import("../node/downloader.zig").Downloader;

pub const Engine = struct {
    const Self = @This();

    bc: *Blockchain,
    downloader: *Downloader,

    pub fn init(bc: *Blockchain, downloader: *Downloader) Self {
        return .{ .bc = bc, .downloader = downloader };
    }

    pub fn register(self: *Self, allocator: std.mem.Allocator, server: *RpcServer) !void {
        try server.register(allocator, "engine_exchangeCapabilities", @ptrCast(self), Engine.exchangeCapabilities);
    }

    pub fn exchangeCapabilities(_: *Self, _: std.Io, _: std.mem.Allocator) ![]const []const u8 {
        return &[_][]const u8{};
    }
};
