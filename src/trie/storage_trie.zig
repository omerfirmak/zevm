const std = @import("std");
const rlp = @import("rlp");
const Trie = @import("trie.zig").Trie;

pub const StorageTrie = struct {
    inner: Trie,

    pub fn init(allocator: std.mem.Allocator) !@This() {
        return .{ .inner = try Trie.init(allocator) };
    }

    pub fn initFromTrie(inner: Trie) @This() {
        return .{ .inner = inner };
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

    pub fn insert(self: *@This(), keys: []const [32]u8, values: []const ?u256) !void {
        const val_slices = try self.inner.allocator.alloc([]const u8, values.len);
        for (values, val_slices) |value_opt, *s| {
            if (value_opt) |value| {
                var buf = std.array_list.Managed(u8).init(self.inner.allocator);
                try rlp.serialize(u256, self.inner.allocator, value, &buf);
                s.* = buf.items;
            } else {
                s.* = &.{};
            }
        }
        try self.inner.update(keys, val_slices);
    }

    pub fn rootHash(self: *@This()) ![32]u8 {
        return self.inner.rootHash();
    }
};
