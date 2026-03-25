const std = @import("std");
const storage = @import("storage.zig");

// keccak256("") — used to identify accounts with no deployed code
pub const empty_code_hash = 0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470;
// keccak256 of an empty trie — placeholder for accounts with no storage
pub const empty_root_hash = 0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421;

pub const Account = struct {
    nonce: u256,
    balance: u256,
    storage_hash: u256,
    code_hash: u256,
};

pub const Snapshot = struct {
    accounts: usize,
    storage: usize,
    tstorage: usize,
};

pub const State = struct {
    const Self = @This();

    accounts: storage.AccountStorage,
    contract_state: storage.ContractStorage,
    transient_storage: storage.ContractStorage,
    code_storage: storage.CodeStorage,

    pub fn init(gpa: std.mem.Allocator) !Self {
        var code_storage = storage.CodeStorage.empty;
        try code_storage.ensureTotalCapacity(gpa, 1_000);
        return Self{
            .accounts = try storage.AccountStorage.init(gpa, 10_000, 10_000),
            .contract_state = try storage.ContractStorage.init(gpa, 10_000, 10_000),
            .transient_storage = try storage.ContractStorage.init(gpa, 500_000, 500_000),
            .code_storage = code_storage,
        };
    }

    pub fn deinit(self: *Self, gpa: std.mem.Allocator) void {
        self.accounts.deinit(gpa);
        self.contract_state.deinit(gpa);
        self.transient_storage.deinit(gpa);
    }

    pub fn snapshot(self: *Self) Snapshot {
        return .{
            .accounts = self.accounts.snapshot(),
            .storage = self.contract_state.snapshot(),
            .tstorage = self.transient_storage.snapshot(),
        };
    }

    pub fn revert(self: *Self, snapshot_ids: Snapshot) void {
        self.accounts.revert(snapshot_ids.accounts);
        self.contract_state.revert(snapshot_ids.storage);
        self.transient_storage.revert(snapshot_ids.tstorage);
    }
};
