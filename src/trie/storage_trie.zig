// Copyright (c) 2025-2026 zevm authors
// SPDX-License-Identifier: MIT OR Apache-2.0

const std = @import("std");
const rlp = @import("rlp");
const Trie = @import("trie.zig").Trie;
const NodeCollector = @import("trie.zig").NodeCollector;

pub const StorageTrie = struct {
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

    pub fn get(self: *const @This(), key: [32]u8) !u256 {
        const trie_value = try self.inner.get(key);
        if (trie_value) |buf| {
            var value: u256 = undefined;
            _ = try rlp.deserialize(u256, undefined, buf, &value);
            return value;
        } else {
            return 0;
        }
    }

    pub fn insert(self: *@This(), keys: []const [32]u8, values: []const u256) !void {
        const val_slices = try self.inner.allocator.alloc([]const u8, values.len);
        var has_deletions = false;
        for (values, val_slices) |value, *s| {
            if (value > 0) {
                var buf = std.array_list.Managed(u8).init(self.inner.allocator);
                try rlp.serialize(u256, self.inner.allocator, value, &buf);
                s.* = buf.items;
            } else {
                s.* = &.{};
                has_deletions = true;
            }
        }
        if (has_deletions) try self.inner.update(keys, val_slices) else try self.inner.updateNoDeletions(keys, val_slices);
    }

    pub fn rootHash(self: *@This()) ![32]u8 {
        return self.inner.rootHash();
    }
};
