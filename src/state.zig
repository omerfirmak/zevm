const std = @import("std");
const storage = @import("storage.zig");

// todo: account type
pub const Account = struct {};

pub const State = struct {
    const Self = @This();

    accounts: storage.AccountStorage,
    contract_state: storage.ContractStorage,
    transient_storage: storage.ContractStorage,

    pub fn init(gpa: std.mem.Allocator) !Self {
        return Self{
            .accounts = try storage.AccountStorage.init(gpa, 10_000, 10_000),
            .contract_state = try storage.ContractStorage.init(gpa, 10_000, 10_000),
            .transient_storage = try storage.ContractStorage.init(gpa, 10_000, 10_000),
        };
    }

    pub fn deinit(self: *Self, gpa: std.mem.Allocator) void {
        self.accounts.deinit(gpa);
        self.contract_state.deinit(gpa);
        self.transient_storage.deinit(gpa);
    }
};
