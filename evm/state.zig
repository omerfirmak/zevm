const std = @import("std");
const types = @import("types");
const storage = @import("storage.zig");
const ops = @import("ops.zig");
const Bytecode = @import("bytecode.zig").Bytecode;
const Config = @import("config.zig").Config;
pub const CommittedState = @import("committed_state").CommittedState;

pub const Snapshot = struct {
    accounts: usize,
    storage: usize,
    tstorage: usize,
};

pub const State = struct {
    const Self = @This();

    committed_state: *const CommittedState,

    accounts: storage.AccountStorage,
    contract_state: storage.ContractStorage,
    transient_storage: storage.TransientStorage,
    code_storage: storage.CodeStorage,

    deployed_bytecode_allocator: std.heap.FixedBufferAllocator,

    pub fn init(gpa: std.mem.Allocator, committed_state: *const CommittedState, deployed_bytecode_buffer: usize) !Self {
        var code_storage = storage.CodeStorage.empty;
        try code_storage.ensureTotalCapacity(gpa, 1_000);
        return Self{
            .committed_state = committed_state,
            .accounts = try storage.AccountStorage.init(gpa, 10_000, 100_000, .{ .inner = committed_state }),
            .contract_state = try storage.ContractStorage.init(gpa, 10_000, 100_000, .{ .inner = committed_state }),
            .transient_storage = try storage.TransientStorage.init(gpa, 500_000, 500_000, {}),
            .code_storage = code_storage,
            .deployed_bytecode_allocator = std.heap.FixedBufferAllocator.init(try gpa.alloc(u8, deployed_bytecode_buffer)),
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

    pub fn get_code(self: *Self, hash: [32]u8, comptime cfg: Config) Bytecode {
        if (self.code_storage.get(hash)) |b| {
            return b;
        }
        const code = self.committed_state.code(hash);
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
