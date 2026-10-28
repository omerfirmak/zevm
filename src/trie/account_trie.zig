// Copyright (c) 2025-2026 zevm authors
// SPDX-License-Identifier: MIT OR Apache-2.0

const std = @import("std");
const rlp = @import("rlp");
const types = @import("../types.zig");
const Trie = @import("trie.zig").Trie;
const NodeCollector = @import("trie.zig").NodeCollector;

pub const AccountTrie = struct {
    inner: Trie,

    pub fn init(allocator: std.mem.Allocator) @This() {
        return .{ .inner = Trie.init(allocator) };
    }

    pub fn initFromTrie(inner: Trie) @This() {
        return .{ .inner = inner };
    }

    pub fn withCollector(self: @This(), collector: *NodeCollector) @This() {
        return .{ .inner = self.inner.withCollector(collector) };
    }

    pub fn get(self: *const @This(), key: [32]u8) !types.Account {
        const trie_value = try self.inner.get(key);
        if (trie_value) |buf| {
            var account: types.Account = undefined;
            _ = try rlp.deserialize(types.Account, undefined, buf, &account);
            return account;
        } else {
            return .{
                .balance = 0,
                .nonce = 0,
                .code_hash = types.empty_code_hash,
                .storage_hash = types.empty_root_hash,
            };
        }
    }

    pub fn update(self: *@This(), keys: []const [32]u8, accounts: []const ?types.Account) !void {
        const val_slices = try self.inner.allocator.alloc([]const u8, accounts.len);
        var has_deletions = false;
        for (accounts, val_slices) |account_opt, *s| {
            if (account_opt) |account| {
                s.* = try self.encode(account);
            } else {
                s.* = &.{};
                has_deletions = true;
            }
        }
        if (has_deletions) try self.inner.update(keys, val_slices) else try self.inner.updateNoDeletions(keys, val_slices);
    }

    pub fn updateUnsorted(self: *@This(), keys: []const [32]u8, accounts: []const ?types.Account) !void {
        const val_slices = try self.inner.allocator.alloc([]const u8, accounts.len);
        for (accounts, val_slices) |account_opt, *s| {
            s.* = if (account_opt) |account| try self.encode(account) else &.{};
        }
        try self.inner.update(keys, val_slices);
    }

    pub fn updateNoDeletions(self: *@This(), keys: []const [32]u8, accounts: []const types.Account) !void {
        const val_slices = try self.inner.allocator.alloc([]const u8, accounts.len);
        for (accounts, val_slices) |account, *s| s.* = try self.encode(account);
        try self.inner.updateNoDeletions(keys, val_slices);
    }

    fn encode(self: *@This(), account: types.Account) ![]const u8 {
        var buf = std.array_list.Managed(u8).init(self.inner.allocator);
        try rlp.serialize(types.Account, self.inner.allocator, account, &buf);
        return buf.items;
    }

    pub fn rootHash(self: *@This()) ![32]u8 {
        return self.inner.rootHash();
    }
};
