const std = @import("std");
const storage = @import("storage.zig");

pub const empty_code_hash = 0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470;
pub const empty_root_hash = 0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421;

pub const Account = struct {
    nonce: u256,
    balance: u256,
    storage_hash: u256,
    code_hash: u256,
};

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
