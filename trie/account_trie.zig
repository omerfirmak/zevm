const std = @import("std");
const rlp = @import("rlp");
const types = @import("types");
const Trie = @import("trie.zig").Trie;

pub const AccountTrie = struct {
    inner: Trie,

    pub fn init(fba: *std.heap.FixedBufferAllocator) !@This() {
        return .{ .inner = try Trie.init(fba) };
    }

    pub fn deinit(self: *@This()) void {
        self.inner.deinit();
    }

    pub fn insert(self: *@This(), keys: []const [32]u8, accounts: []const types.Account) !void {
        const val_slices = try self.inner.allocator.alloc([]const u8, accounts.len);
        for (accounts, val_slices) |account, *s| {
            var buf = std.array_list.Managed(u8).init(self.inner.allocator);
            try rlp.serialize(types.Account, self.inner.allocator, account, &buf);
            s.* = buf.items;
        }
        try self.inner.update(keys, val_slices);
    }

    pub fn rootHash(self: *@This()) ![32]u8 {
        return self.inner.rootHash();
    }
};
