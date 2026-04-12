const std = @import("std");
const types = @import("types");

pub const CommittedState = struct {
    account_map: std.AutoHashMap(u160, types.Account),
    storage_map: std.AutoHashMap(types.StorageLookup, u256),
    code_map: std.AutoHashMap(u256, []const u8),

    pub fn init(alloc: std.mem.Allocator) @This() {
        return .{
            .account_map = std.AutoHashMap(u160, types.Account).init(alloc),
            .storage_map = std.AutoHashMap(types.StorageLookup, u256).init(alloc),
            .code_map = std.AutoHashMap(u256, []const u8).init(alloc),
        };
    }

    pub fn deinit(self: *@This()) void {
        self.account_map.deinit();
        self.storage_map.deinit();
        self.code_map.deinit();
    }

    pub fn account(self: *const @This(), addr: u160) types.Account {
        return self.account_map.get(addr) orelse .{
            .nonce = 0,
            .balance = 0,
            .code_hash = types.empty_code_hash,
            .storage_hash = types.empty_root_hash,
        };
    }

    pub fn storage(self: *const @This(), key: types.StorageLookup) u256 {
        return self.storage_map.get(key) orelse 0;
    }

    pub fn code(self: *const @This(), hash: u256) ?[]const u8 {
        return self.code_map.get(hash);
    }
};
