const std = @import("std");
const rlp = @import("rlp");
const trie = @import("../trie/trie.zig");
const kv = @import("kv.zig");
const types = @import("../types.zig");

const EthDb = @import("eth.zig").Eth;

pub const StorageTrieResolver = struct {
    eth: *EthDb,
    txn: kv.Transaction,
    account_hash: [32]u8,

    pub fn resolver(self: *StorageTrieResolver) trie.Trie.NodeResolver {
        return .{ .ptr = self, .resolveFn = resolve };
    }

    fn resolve(ptr: *anyopaque, _: std.mem.Allocator, path: []const u8, _: [32]u8) anyerror!?trie.Trie.NodeResolver.Resolved {
        const self: *StorageTrieResolver = @ptrCast(@alignCast(ptr));

        if (try self.eth.readStorageTrie(self.txn, self.account_hash, path)) |encoded| {
            return .{ .rlp = encoded };
        } else return try self.resolveLeaf(path);
    }

    fn resolveLeaf(self: StorageTrieResolver, path: []const u8) !?trie.Trie.NodeResolver.Resolved {
        const slot_hash, const value = try self.eth.seekStorage(self.txn, self.account_hash, try pathStart(path)) orelse return null;
        var nibbles_buf: [64]u8 = undefined;
        const nibbles = trie.writeHexKey(&slot_hash, &nibbles_buf);
        if (!std.mem.startsWith(u8, nibbles, path)) return null;
        return .{ .node = trie.Node.Leaf.init(nibbles[path.len..], value) };
    }
};

pub const AccountTrieResolver = struct {
    eth: *EthDb,
    txn: kv.Transaction,

    pub fn resolver(self: *AccountTrieResolver) trie.Trie.NodeResolver {
        return .{ .ptr = self, .resolveFn = resolve };
    }

    fn resolve(ptr: *anyopaque, allocator: std.mem.Allocator, path: []const u8, _: [32]u8) anyerror!?trie.Trie.NodeResolver.Resolved {
        const self: *AccountTrieResolver = @ptrCast(@alignCast(ptr));

        if (try self.eth.readAccountTrie(self.txn, path)) |encoded| {
            return .{ .rlp = encoded };
        } else return try self.resolveLeaf(allocator, path);
    }

    fn resolveLeaf(self: AccountTrieResolver, allocator: std.mem.Allocator, path: []const u8) !?trie.Trie.NodeResolver.Resolved {
        const account_hash, const account = try self.eth.seekAccount(self.txn, try pathStart(path)) orelse return null;
        var nibbles_buf: [64]u8 = undefined;
        const nibbles = trie.writeHexKey(&account_hash, &nibbles_buf);
        if (!std.mem.startsWith(u8, nibbles, path)) return null;

        var list = std.array_list.Managed(u8).init(allocator);
        try rlp.serialize(types.Account, allocator, account, &list);
        return .{ .node = trie.Node.Leaf.init(nibbles[path.len..], list.items) };
    }
};

fn pathStart(path: []const u8) ![32]u8 {
    if (path.len > 64) return error.TrieNodePathTooLong;
    var start: [32]u8 = @splat(0);
    for (path, 0..) |nibble, i| start[i / 2] |= if (i % 2 == 0) nibble << 4 else nibble;
    return start;
}
