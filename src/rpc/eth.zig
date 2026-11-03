// Copyright (c) 2025-2026 zevm authors
// SPDX-License-Identifier: MIT OR Apache-2.0

const std = @import("std");
const RpcServer = @import("jsonrpc.zig").Server;
const Blockchain = @import("../node/blockchain.zig").Blockchain;
const Downloader = @import("../node/downloader.zig").Downloader;
const hex = @import("hex.zig");

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

    pub fn blockNumber(self: *Self, _: std.Io, _: std.mem.Allocator) !hex.Number(u64) {
        return .init((try self.bc.head()).number);
    }

    pub fn chainId(self: *Self, _: std.Io, _: std.mem.Allocator) !hex.Number(u64) {
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
        startingBlock: hex.Number(u64),
        currentBlock: hex.Number(u64),
        highestBlock: hex.Number(u64),
    },

    pub fn jsonStringify(self: *const Syncing, jws: anytype) !void {
        switch (self.*) {
            .not_syncing => try jws.write(false),
            .syncing => |progress| try jws.write(progress),
        }
    }
};
