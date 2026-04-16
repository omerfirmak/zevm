const std = @import("std");
const rlp = @import("rlp");
const types = @import("types");
const Trie = @import("trie.zig").Trie;
const Keccak256 = std.crypto.hash.sha3.Keccak256;

pub const AccountTrie = struct {
    inner: Trie,

    pub fn init(fba: *std.heap.FixedBufferAllocator) !@This() {
        return .{ .inner = try Trie.init(fba) };
    }

    pub fn deinit(self: *@This()) void {
        self.inner.deinit();
    }

    pub fn insert(self: *@This(), key: [32]u8, account: types.Account) !void {
        var val_buf = std.array_list.Managed(u8).init(self.inner.allocator);
        try rlp.serialize(types.Account, self.inner.allocator, account, &val_buf);
        try self.inner.update(&key, val_buf.items);
    }

    pub fn rootHash(self: *@This()) ![32]u8 {
        return self.inner.rootHash();
    }
};
