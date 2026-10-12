// Copyright (c) 2025-2026 zevm authors
// SPDX-License-Identifier: MIT OR Apache-2.0

const std = @import("std");
const types = @import("../types.zig");
const storage = @import("storage.zig");
const ops = @import("ops.zig");
const BlockAccessList = @import("../processor/bal.zig").Prepared;
const Bytecode = @import("bytecode.zig").Bytecode;
const Config = @import("config.zig").Config;
pub const CommittedState = @import("committed_state.zig").CommittedState;
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
    /// Optional owner-managed allocator for raw code copies and decoded pages.
    /// See `initWithCodeAllocator` for the lifetime contract.
    code_allocator: ?std.mem.Allocator = null,
    /// Opt in only if `committed_state.code` returns immutable bytes that stay
    /// alive until `code_storage` is cleared and every active frame has
    /// returned; `get_code` then references them instead of copying. Newly
    /// deployed code is always copied because its source is EVM scratch.
    ///
    /// Under the same promise, a committed state that declares
    /// `codeAnalysis(hash) ?*const Bytecode.Analysis` lends its precomputed
    /// instruction analysis to `get_code`, which then never scans the code
    /// (see `Bytecode.initWithAnalysis`). The analysis must be bound to the
    /// hash it is returned for and must outlive every frame as the bytes do.
    borrow_committed_code: bool = false,

    pub fn init(gpa: std.mem.Allocator, committed_state: *const CommittedState, caps: Capacities) !Self {
        return initWithCodeAllocator(gpa, committed_state, caps, null);
    }

    /// Like `init`, but decoded code (raw copies, page tables and lazily
    /// decoded pages) is allocated from `code_allocator` instead of the fixed
    /// `caps.bytecode_buf` buffer. Pages are decoded while frames execute, so
    /// the allocator must keep every allocation stable until all EVM calls
    /// have returned and `code_storage` has been cleared. `State` never frees
    /// individual code allocations: the caller owns the allocator's reset or
    /// deinitialization (an arena fits), and `deinit` only frees the default
    /// buffer, which is empty in this mode.
    pub fn initWithCodeAllocator(gpa: std.mem.Allocator, committed_state: *const CommittedState, caps: Capacities, code_allocator: ?std.mem.Allocator) !Self {
        var code_storage = storage.CodeStorage.empty;
        try code_storage.ensureTotalCapacity(gpa, caps.code_slots);
        return Self{
            .committed_state = committed_state,
            .accounts = try storage.AccountStorage.init(gpa, caps.account_dirties, caps.account_journal, .{ .inner = committed_state }),
            .contract_state = try storage.ContractStorage.init(gpa, caps.contract_dirties, caps.contract_journal, .{ .inner = committed_state }),
            .transient_storage = try storage.TransientStorage.init(gpa, caps.transient_dirties, caps.transient_journal, {}),
            .code_storage = code_storage,
            .deployed_bytecode_allocator = std.heap.FixedBufferAllocator.init(try gpa.alloc(u8, if (code_allocator == null) caps.bytecode_buf else 0)),
            .code_allocator = code_allocator,
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
        self.accounts.journal.items.len = 0;
        self.contract_state.journal.items.len = 0;
        self.transient_storage.clearViaJournal();
    }

    pub fn clearAccount(self: *Self, addr: u160, comptime cfg: Config) void {
        var balance: u256 = 0;
        if (cfg.fork.isEnabled(.Amsterdam))
            balance = if (self.accounts.dirties.get(addr)) |acct| acct.balance else 0;
        _ = self.accounts.dirties.putAssumeCapacity(addr, .{
            .balance = balance,
            .nonce = 0,
            .code_hash = types.empty_code_hash,
            .storage_hash = types.empty_root_hash,
        });
    }

    pub fn get_code(self: *Self, hash: [32]u8, comptime cfg: Config) !Bytecode {
        if (self.code_storage.get(hash)) |b| {
            return b;
        }
        const code = try self.committed_state.code(hash);
        // The host's analysis shares the lifetime promise of its borrowed
        // bytes, so it is consulted only while borrowing.
        const analysis = if (self.borrow_committed_code) hostAnalysis(CommittedState, self.committed_state, hash) else null;
        try self.cacheCode(hash, code, !self.borrow_committed_code, analysis, cfg);
        return self.code_storage.get(hash) orelse unreachable;
    }

    pub fn deploy_code(self: *Self, hash: [32]u8, code: []const u8, comptime cfg: Config) !void {
        return self.cacheCode(hash, code, true, null, cfg);
    }

    fn cacheCode(self: *Self, hash: [32]u8, code: []const u8, copy: bool, analysis: ?*const Bytecode.Analysis, comptime cfg: Config) !void {
        if (self.code_storage.contains(hash)) return;
        // Exhaust the bounded cache with an error, never an
        // assume-capacity assertion or an out-of-bounds write.
        if (self.code_storage.size >= self.code_storage.capacity() * 80 / 100)
            return error.OutOfMemory;

        const allocator = self.code_allocator orelse self.deployed_bytecode_allocator.allocator();
        const code_bytes = if (copy) try allocator.dupe(u8, code) else code;
        const bytecode = try Bytecode.initWithAnalysis(allocator, code_bytes, cfg, analysis);
        self.code_storage.putAssumeCapacity(hash, bytecode);
    }
};

/// Precomputed `Bytecode.Analysis` that `host` keeps for the committed code
/// under `hash`, if `Host` declares `codeAnalysis`; null otherwise or on a
/// miss. The host binds the result to that hash and keeps it alive and
/// unchanged as long as the borrowed code bytes.
fn hostAnalysis(comptime Host: type, host: *const Host, hash: [32]u8) ?*const Bytecode.Analysis {
    if (@hasDecl(Host, "codeAnalysis")) return host.codeAnalysis(hash);
    return null;
}

test "external code allocator owns decoded code and deployment always copies" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const cfg: Config = .{ .fork = comptime Spec.fromFork(.Amsterdam) };
    const committed: CommittedState = .{};
    // Pages decoded during execution outlive the State until the owner resets
    // the code allocator, so it is deinitialized after the State below.
    var code_arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer code_arena.deinit();
    var state = try State.initWithCodeAllocator(a, &committed, cfg.fork.stateCapacities(1_000_000), code_arena.allocator());
    defer state.deinit(a);
    try std.testing.expectEqual(0, state.deployed_bytecode_allocator.buffer.len);
    // Borrowing only applies to committed code; deployed bytes come from EVM scratch.
    state.borrow_committed_code = true;
    var deployed = [_]u8{ 0x60, 0x01, 0x5b, 0x00 };
    const hash: [32]u8 = @splat(0x11);
    try state.deploy_code(hash, &deployed, cfg);
    deployed[1] = 0xff;
    var bytecode = try state.get_code(hash, cfg);
    try std.testing.expect(bytecode.bytes.ptr != &deployed);
    try std.testing.expectEqual(1, bytecode.bytes[1]);
    try std.testing.expectEqual(0, state.deployed_bytecode_allocator.end_index);
    // Decoded code lives in the external allocator; the fixed buffer is untouched.
    const before = code_arena.queryCapacity();
    try std.testing.expect(before > 0);
    try std.testing.expect((try bytecode.isValidJumpDest(2, cfg)) != null);
    try std.testing.expectEqual(0, state.deployed_bytecode_allocator.end_index);
    // Committed code is unavailable in the empty host, with or without borrowing.
    try std.testing.expectError(error.NotFound, state.get_code(@splat(0x22), cfg));
    state.borrow_committed_code = false;
    try std.testing.expectError(error.NotFound, state.get_code(@splat(0x22), cfg));
}

test "code storage falls back to the fixed buffer without an external allocator" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const cfg: Config = .{ .fork = comptime Spec.fromFork(.Amsterdam) };
    const committed: CommittedState = .{};
    var state = try State.init(a, &committed, cfg.fork.stateCapacities(1_000_000));
    defer state.deinit(a);
    try std.testing.expectEqual(null, state.code_allocator);
    try std.testing.expect(!state.borrow_committed_code);
    const code = [_]u8{ 0x5b, 0x00 };
    try state.deploy_code(@splat(0x33), &code, cfg);
    try std.testing.expect(state.deployed_bytecode_allocator.end_index >= code.len);
    const stored = state.code_storage.get(@splat(0x33)).?;
    try std.testing.expect(stored.bytes.ptr != &code);
}

test "full decoded code map rejects new code without consuming bytecode capacity" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const cfg: Config = .{ .fork = comptime Spec.fromFork(.Amsterdam) };
    const committed: CommittedState = .{};
    var caps = cfg.fork.stateCapacities(1_000_000);
    caps.code_slots = 1;
    var state = try State.init(a, &committed, caps);
    const limit = state.code_storage.capacity() * 80 / 100;
    for (0..limit) |i| {
        var hash: [32]u8 = @splat(0);
        std.mem.writeInt(u32, hash[0..4], @intCast(i), .big);
        try state.deploy_code(hash, &.{0}, cfg);
    }
    const used = state.deployed_bytecode_allocator.end_index;
    // Existing entries remain usable even when the map is full.
    try state.deploy_code(@splat(0), &.{0}, cfg);
    try std.testing.expectError(error.OutOfMemory, state.deploy_code(@splat(0xff), &.{0}, cfg));
    try std.testing.expectEqual(limit, state.code_storage.size);
    try std.testing.expectEqual(used, state.deployed_bytecode_allocator.end_index);
}

/// Host that lends one analysis for a single hash, as a code cache would.
const AnalysisHost = struct {
    analysis: Bytecode.Analysis,
    bound_hash: [32]u8,

    pub fn codeAnalysis(self: *const @This(), hash: [32]u8) ?*const Bytecode.Analysis {
        return if (std.mem.eql(u8, &hash, &self.bound_hash)) &self.analysis else null;
    }
};

test "a host analysis is found through codeAnalysis for its hash only" {
    const a = std.testing.allocator;
    const cfg: Config = .{ .fork = comptime Spec.fromFork(.Amsterdam) };
    const code = [_]u8{ 0x60, 0x5b, 0x5b, 0x00 };
    var host: AnalysisHost = .{ .analysis = try Bytecode.Analysis.init(a, &code, cfg), .bound_hash = @splat(0xaa) };
    defer host.analysis.deinit(a);
    try std.testing.expectEqual(&host.analysis, hostAnalysis(AnalysisHost, &host, @splat(0xaa)));
    try std.testing.expectEqual(null, hostAnalysis(AnalysisHost, &host, @splat(0xab)));
    // A host without the declaration, like the empty committed state, lends nothing.
    const bare: struct {} = .{};
    try std.testing.expectEqual(null, hostAnalysis(@TypeOf(bare), &bare, @splat(0xaa)));
}

test "committed code borrows a compatible host analysis and deployed code never does" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const cfg: Config = .{ .fork = comptime Spec.fromFork(.Amsterdam) };
    const committed: CommittedState = .{};
    var code_arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer code_arena.deinit();
    // PUSH1 of a byte that looks like JUMPDEST, a real JUMPDEST, STOP. The
    // analysis outlives the state, as a host cache entry would.
    const code = [_]u8{ 0x60, 0x5b, 0x5b, 0x00 };
    const analysis = try Bytecode.Analysis.init(std.testing.allocator, &code, cfg);
    defer analysis.deinit(std.testing.allocator);
    var state = try State.initWithCodeAllocator(a, &committed, cfg.fork.stateCapacities(1_000_000), code_arena.allocator());
    defer state.deinit(a);
    state.borrow_committed_code = true;

    // The committed path with a provider borrows both the bytes and the bitmap.
    const hash: [32]u8 = @splat(0x44);
    try state.cacheCode(hash, &code, false, &analysis, cfg);
    var borrowed = try state.get_code(hash, cfg);
    try std.testing.expect(borrowed.bytes.ptr == &code);
    try std.testing.expect(borrowed.borrowsAnalysis());
    try std.testing.expectEqual(null, try borrowed.isValidJumpDest(1, cfg));
    try std.testing.expect((try borrowed.isValidJumpDest(2, cfg)) != null);
    // Deployment copies the bytes and always scans on its own.
    const deployed_hash: [32]u8 = @splat(0x55);
    try state.deploy_code(deployed_hash, &code, cfg);
    var deployed = try state.get_code(deployed_hash, cfg);
    try std.testing.expect(deployed.bytes.ptr != &code);
    try std.testing.expect(!deployed.borrowsAnalysis());
    try std.testing.expectEqual(null, try deployed.isValidJumpDest(1, cfg));
    try std.testing.expect((try deployed.isValidJumpDest(2, cfg)) != null);
    // An analysis computed under another immediate rule is offered but not borrowed.
    const osaka: Config = .{ .fork = comptime Spec.fromFork(.Osaka) };
    const foreign_hash: [32]u8 = @splat(0x66);
    try state.cacheCode(foreign_hash, &code, false, &analysis, osaka);
    var foreign = try state.get_code(foreign_hash, osaka);
    try std.testing.expect(!foreign.borrowsAnalysis());
    try std.testing.expect((try foreign.isValidJumpDest(2, osaka)) != null);
}
