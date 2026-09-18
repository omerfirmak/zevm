const std = @import("std");
const kv = @import("kv.zig");
const types = @import("../types.zig");
const rlp = @import("rlp");

pub const Eth = struct {
    const Self = @This();

    kv_store: *kv.Store,

    pub fn init(kv_store: *kv.Store) Self {
        return .{ .kv_store = kv_store };
    }

    pub fn readAccount(self: *Self, allocator: std.mem.Allocator, txn: kv.Transaction, hash: [32]u8) !?types.Account {
        const table = self.kv_store.table(txn, .accounts);

        const bytes = try table.get(&hash) orelse return null;

        var acc: SlimAccount = undefined;
        _ = try rlp.deserialize(SlimAccount, allocator, bytes, &acc);

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
    try std.testing.expect(try eth.readAccount(std.testing.allocator, txn, hash) == null);

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
        const read_acc = try eth.readAccount(std.testing.allocator, txn, hash);
        try std.testing.expectEqual(acc, read_acc);
    }

    try txn.commit();
    try std.testing.expect(try eth.readAccount(std.testing.allocator, try store.transaction_ro(), hash) != null);
}
