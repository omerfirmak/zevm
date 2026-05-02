const std = @import("std");
const types = @import("types");
const storage = @import("storage.zig");
const ops = @import("ops.zig");
const Bytecode = @import("bytecode.zig").Bytecode;
const Config = @import("config.zig").Config;
pub const CommittedState = @import("committed_state").CommittedState;
const Spec = @import("spec.zig").Spec;

pub const Snapshot = struct {
    accounts: usize,
    storage: usize,
    tstorage: usize,
};

/// Pre-allocation sizes for State. Use Spec.stateCapacities(gas_limit) to
/// derive tight bounds from the transaction gas limit and current gas costs.
pub const Capacities = Spec.StateCapacities;

pub const State = struct {
    const Self = @This();

    committed_state: *const CommittedState,

    accounts: storage.AccountStorage,
    contract_state: storage.ContractStorage,
    transient_storage: storage.TransientStorage,
    code_storage: storage.CodeStorage,

    deployed_bytecode_allocator: std.heap.FixedBufferAllocator,

    pub fn init(gpa: std.mem.Allocator, committed_state: *const CommittedState, caps: Capacities) !Self {
        var code_storage = storage.CodeStorage.empty;
        try code_storage.ensureTotalCapacity(gpa, caps.code_slots);
        return Self{
            .committed_state = committed_state,
            .accounts = try storage.AccountStorage.init(gpa, caps.account_dirties, caps.account_journal, .{ .inner = committed_state }),
            .contract_state = try storage.ContractStorage.init(gpa, caps.contract_dirties, caps.contract_journal, .{ .inner = committed_state }),
            .transient_storage = try storage.TransientStorage.init(gpa, caps.transient_dirties, caps.transient_journal, {}),
            .code_storage = code_storage,
            .deployed_bytecode_allocator = std.heap.FixedBufferAllocator.init(try gpa.alloc(u8, caps.bytecode_buf)),
        };
    }

    pub fn deinit(self: *Self, gpa: std.mem.Allocator) void {
        self.code_storage.deinit(gpa);
        self.accounts.deinit(gpa);
        self.contract_state.deinit(gpa);
        self.transient_storage.deinit(gpa);
        gpa.free(self.deployed_bytecode_allocator.buffer);
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

    pub fn clearTxState(self: *Self) void {
        self.accounts.journal.clearRetainingCapacity();
        self.contract_state.journal.clearRetainingCapacity();
        self.transient_storage.dirties.clearRetainingCapacity();
        self.transient_storage.journal.clearRetainingCapacity();
    }

    pub fn clearAccount(self: *Self, addr: u160) void {
        _ = self.accounts.dirties.remove(addr);
    }

    pub fn get_code(self: *Self, hash: [32]u8, comptime cfg: Config) !Bytecode {
        if (self.code_storage.get(hash)) |b| {
            return b;
        }
        const code = try self.committed_state.code(hash);
        self.deploy_code(hash, code, cfg);
        return self.code_storage.get(hash) orelse unreachable;
    }

    pub fn deploy_code(self: *Self, hash: [32]u8, code: []const u8, comptime cfg: Config) void {
        const allocator = self.deployed_bytecode_allocator.allocator();
        const code_bytes = allocator.dupe(u8, code) catch unreachable;
        const bytecode = Bytecode.init(allocator, code_bytes, cfg) catch unreachable;
        self.code_storage.putAssumeCapacity(hash, bytecode);
    }
};
