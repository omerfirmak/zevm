const std = @import("std");
const rlp = @import("rlp");
const types = @import("../types.zig");
const Trie = @import("trie.zig").Trie;

pub const AccountTrie = struct {
    inner: Trie,

    pub fn init(allocator: std.mem.Allocator) !@This() {
        return .{ .inner = try Trie.init(allocator) };
    }

    pub fn initFromTrie(inner: Trie) @This() {
        return .{ .inner = inner };
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
