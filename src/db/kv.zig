const std = @import("std");
const lmdbx = @import("lmdbx");

pub const Transaction = lmdbx.Transaction;
pub const Iterator = lmdbx.Cursor;

pub const Table = enum {
    accounts,
    storage,
    codes,

    pub fn options(self: Table) lmdbx.Database.Options {
        return switch (self) {
            .storage => .{ .dup_sort = true },
            else => .{},
        };
    }
};

const table_count = std.enums.values(Table).len;

pub const Store = struct {
    env: lmdbx.Environment,
    dbis: [table_count]lmdbx.Database.DBI,

    pub fn init(allocator: std.mem.Allocator, path: []const u8) !Store {
        const init_path = try allocator.dupeSentinel(u8, path, 0);
        defer allocator.free(init_path);

        const env = try lmdbx.Environment.init(init_path, .{
            .max_dbs = table_count,
            .safe_nosync = true,
            .geometry = .{
                .lower_size = 0,
                .upper_size = 8 << 40,
                .growth_step = 4 << 30,
                .shrink_threshold = 0,
            },
        });
        errdefer env.deinit() catch {};

        var dbis: [table_count]lmdbx.Database.DBI = undefined;

        const txn = try env.transaction(.{ .mode = .ReadWrite });
        errdefer txn.abort() catch {};

        for (std.enums.values(Table)) |t| {
            var opts = t.options();
            opts.create = true;
            const db = try txn.database(@tagName(t), opts);
            dbis[@intFromEnum(t)] = db.dbi;
        }

        try txn.commit();

        return .{ .env = env, .dbis = dbis };
    }

    pub fn transaction_ro(self: *const Store) !Transaction {
        return try self.env.transaction(.{ .mode = .ReadOnly });
    }

    pub fn transaction_rw(self: *const Store) !Transaction {
        return try self.env.transaction(.{ .mode = .ReadWrite });
    }

    pub fn table(self: *const Store, txn: Transaction, t: Table) lmdbx.Database {
        return .{ .txn = txn, .dbi = self.dbis[@intFromEnum(t)] };
    }
};
