// Copyright (c) 2025-2026 zevm authors
// SPDX-License-Identifier: MIT OR Apache-2.0

const std = @import("std");
const kv = @import("kv.zig");
const types = @import("../types.zig");
const rlp = @import("rlp");
const lmdbx = @import("lmdbx");
const trie = @import("../trie/trie.zig");

pub const Eth = struct {
    const Self = @This();

    kv_store: *kv.Store,

    pub fn init(kv_store: *kv.Store) Self {
        return .{ .kv_store = kv_store };
    }

    pub fn readAccount(self: *Self, txn: kv.Transaction, hash: [32]u8) !?types.Account {
        const table = self.kv_store.table(txn, .accounts);
        const bytes = try table.get(&hash) orelse return null;
        return try decodeAccount(bytes);
    }

    pub fn decodeAccount(rlp_bytes: []const u8) !types.Account {
        var acc: SlimAccount = undefined;
        _ = try rlp.deserialize(SlimAccount, undefined, rlp_bytes, &acc);

        return .{
            .nonce = acc.nonce,
            .balance = acc.balance,
            .storage_hash = if (acc.root.len == 32)
                acc.root[0..32].*
            else
                types.empty_root_hash,
            .code_hash = if (acc.code_hash.len == 32)
                acc.code_hash[0..32].*
            else
                types.empty_code_hash,
        };
    }

    pub fn writeAccount(self: *Self, allocator: std.mem.Allocator, txn: kv.Transaction, hash: [32]u8, account: types.Account) !void {
        const table = self.kv_store.table(txn, .accounts);

        var list = std.array_list.Managed(u8).init(allocator);
        defer list.deinit();

        try rlp.serialize(SlimAccount, allocator, .{
            .nonce = @intCast(account.nonce),
            .balance = account.balance,
            .root = if (std.mem.eql(u8, &types.empty_root_hash, &account.storage_hash))
                &[_]u8{}
            else
                @constCast(&account.storage_hash),
            .code_hash = if (std.mem.eql(u8, &types.empty_code_hash, &account.code_hash))
                &[_]u8{}
            else
                @constCast(&account.code_hash),
        }, &list);

        try table.set(&hash, list.items, .Upsert);
    }

    const max_value_rlp_len = 33;

    fn encodeSlot(buf: *[32 + max_value_rlp_len]u8, slot_hash: [32]u8, value_rlp: []const u8) ![]const u8 {
        if (value_rlp.len > max_value_rlp_len) return error.StorageValueTooLong;
        @memcpy(buf[0..32], &slot_hash);
        @memcpy(buf[32..][0..value_rlp.len], value_rlp);
        return buf[0 .. 32 + value_rlp.len];
    }

    pub fn appendStorage(self: *Self, txn: kv.Transaction, account_hash: [32]u8, slot_hashes: []const [32]u8, values_rlp: []const []const u8, append_key: bool) !void {
        const cursor = try self.kv_store.table(txn, .storage).cursor();
        defer cursor.deinit();
        var buf: [32 + max_value_rlp_len]u8 = undefined;
        const flags: lmdbx.Database.SetFlag = if (append_key) lmdbx.Database.SetFlag.AppendDup.with(.Append) else .AppendDup;
        for (slot_hashes, values_rlp) |slot_hash, value_rlp| {
            try cursor.put(&account_hash, try encodeSlot(&buf, slot_hash, value_rlp), flags);
        }
    }

    pub fn seekStorage(self: *Self, txn: kv.Transaction, account_hash: [32]u8, start: [32]u8) !?struct { [32]u8, []const u8 } {
        const cursor = try self.kv_store.table(txn, .storage).cursor();
        defer cursor.deinit();

        const res = try cursor.seekDupLowerBound(&account_hash, &start) orelse return null;
        if (res.entry.value.len < 32) return error.MalformedStorageEntry;
        return .{ res.entry.value[0..32].*, res.entry.value[32..] };
    }

    pub fn readStorage(self: *Self, txn: kv.Transaction, account_hash: [32]u8, slot_hash: [32]u8) !?[]const u8 {
        const found, const value = try self.seekStorage(txn, account_hash, slot_hash) orelse return null;
        return if (std.mem.eql(u8, &found, &slot_hash)) value else null;
    }

    fn encodeTrieNode(buf: *[768]u8, path: []const u8, blob: []const u8) ![]const u8 {
        if (path.len > 64) return error.TrieNodePathTooLong;
        if (blob.len > buf.len - path.len - 1) return error.TrieNodeTooLong;
        @memcpy(buf[0..path.len], path);
        buf[path.len] = 0xff;
        @memcpy(buf[path.len + 1 ..][0..blob.len], blob);
        return buf[0 .. path.len + 1 + blob.len];
    }

    pub fn appendStorageTrie(self: *Self, txn: kv.Transaction, account_hash: [32]u8, nodes: []const trie.NodeCollector.Node) !void {
        const cursor = try self.kv_store.table(txn, .storage_tries).cursor();
        defer cursor.deinit();
        var buf: [768]u8 = undefined;
        for (nodes) |node| {
            try cursor.put(&account_hash, try encodeTrieNode(
                &buf,
                node.path,
                node.blob,
            ), lmdbx.Database.SetFlag.AppendDup.with(.Append));
        }
    }

    pub fn readStorageTrie(self: *Self, txn: kv.Transaction, account_hash: [32]u8, path: []const u8) !?[]const u8 {
        if (path.len > 64) return error.TrieNodePathTooLong;
        var seek_buf: [65]u8 = undefined;
        @memcpy(seek_buf[0..path.len], path);
        seek_buf[path.len] = 0xff;
        const seek = seek_buf[0 .. path.len + 1];

        const cursor = try self.kv_store.table(txn, .storage_tries).cursor();
        defer cursor.deinit();

        const res = try cursor.seekDupLowerBound(&account_hash, seek) orelse return null;
        if (!std.mem.startsWith(u8, res.entry.value, seek)) return null;
        return res.entry.value[seek.len..];
    }

    pub fn writeStorage(self: *Self, txn: kv.Transaction, account_hash: [32]u8, slot_hash: [32]u8, value: u256) !void {
        const cursor = try self.kv_store.table(txn, .storage).cursor();
        defer cursor.deinit();

        if (try cursor.seekDupLowerBound(&account_hash, &slot_hash)) |res| {
            if (std.mem.startsWith(u8, res.entry.value, &slot_hash))
                try cursor.del(.Current);
        }

        if (value != 0) {
            var buf: [32 + max_value_rlp_len]u8 = undefined;
            var fba = std.heap.FixedBufferAllocator.init(&buf);
            var entry = try std.array_list.Managed(u8).initCapacity(fba.allocator(), buf.len);
            entry.appendSliceAssumeCapacity(&slot_hash);
            try rlp.serialize(u256, fba.allocator(), value, &entry);
            try cursor.put(&account_hash, entry.items, .Upsert);
        }
    }

    pub fn deleteAccount(self: *Self, txn: kv.Transaction, hash: [32]u8) !void {
        const table = self.kv_store.table(txn, .accounts);
        table.delete(&hash) catch |e| {
            if (e != lmdbx.Error.MDBX_NOTFOUND) return e;
        };
    }
};

const SlimAccount = struct {
    nonce: u64,
    balance: u256,
    root: []const u8,
    code_hash: []const u8,
};

test "empty dir" {
    var tmpdir = std.testing.tmpDir(.{});
    try tmpdir.dir.createDir(std.testing.io, "datadir", .default_dir);
    defer tmpdir.cleanup();

    var path: [1024]u8 = undefined;
    const size = try tmpdir.dir.realPathFile(std.testing.io, "datadir", &path);

    var store = try kv.Store.init(std.testing.allocator, path[0..size]);
    var eth = Eth.init(&store);

    const txn = try store.transaction_rw();

    const hash: [32]u8 = @splat(0x44);
    try std.testing.expect(try eth.readAccount(txn, hash) == null);

    const accs = [_]types.Account{
        .{
            .nonce = 1,
            .balance = 2,
            .storage_hash = types.empty_root_hash,
            .code_hash = types.empty_code_hash,
        },
        .{
            .nonce = 3,
            .balance = 4,
            .storage_hash = @splat(0x1),
            .code_hash = types.empty_code_hash,
        },
        .{
            .nonce = 5,
            .balance = 6,
            .storage_hash = types.empty_root_hash,
            .code_hash = @splat(0x2),
        },
        .{
            .nonce = 7,
            .balance = 8,
            .storage_hash = @splat(0x3),
            .code_hash = @splat(0x4),
        },
    };

    for (accs) |acc| {
        try eth.writeAccount(std.testing.allocator, txn, hash, acc);
        const read_acc = try eth.readAccount(txn, hash);
        try std.testing.expectEqual(acc, read_acc);
    }

    try txn.commit();
    try std.testing.expect(try eth.readAccount(try store.transaction_ro(), hash) != null);
}
