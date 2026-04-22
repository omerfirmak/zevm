const std = @import("std");
const rlp = @import("rlp");
const Trie = @import("trie.zig").Trie;

pub const StorageTrie = struct {
    inner: Trie,

    pub fn init(fba: *std.heap.FixedBufferAllocator) !@This() {
        return .{ .inner = try Trie.init(fba) };
    }

    pub fn deinit(self: *@This()) void {
        self.inner.deinit();
    }

    pub fn insert(self: *@This(), keys: []const [32]u8, values: []const u256) !void {
        const val_slices = try self.inner.allocator.alloc([]const u8, values.len);
        for (values, val_slices) |value, *s| {
            var buf = std.array_list.Managed(u8).init(self.inner.allocator);
            try rlp.serialize(u256, self.inner.allocator, value, &buf);
            s.* = buf.items;
        }
        try self.inner.update(keys, val_slices);
    }

    pub fn rootHash(self: *@This()) ![32]u8 {
        return self.inner.rootHash();
    }
};
