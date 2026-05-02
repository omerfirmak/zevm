const std = @import("std");
const types = @import("types");
const evm = @import("../evm/evm.zig");
const rlp = @import("rlp");
const EVM = evm.EVM;
const EvmSpec = @import("../evm/spec.zig");
const State = @import("../evm/state.zig").State;
const ChainSpec = @import("chainspec.zig").ChainSpec;
const secp256k1 = @import("zig-eth-secp256k1");
const Keccak256 = std.crypto.hash.sha3.Keccak256;
const Sha256 = std.crypto.hash.sha2.Sha256;
const blobBaseFee = @import("../blob_fee.zig").blobBaseFee;
const ecrecover = @import("../curve.zig").ecrecover;
const Trie = @import("../trie/trie.zig").Trie;
const empty_root_hash = @import("../trie/trie.zig").empty_root_hash;

const Errors = error{
    GasLimitTooHigh,
    GasLimitTooLow,
    GasLimitLessThanMinimum,
    GasLimitExceeded,
    InvalidTimestamp,
    InvalidBlockNumber,
    ExtraDataTooLong,
    InvalidDifficulty,
    InvalidNonce,
    InvalidUncles,
    InvalidBaseFee,
    BlockRlpTooBig,
    InsufficientGas,
    MismatchedGasUsed,
    MismatchedLogsBloom,
    InvalidBlobGasUsed,
    MismatchedBlobGasUsed,
    MismatchedExcessBlobGas,
    MismatchedRequestsHash,
    MismatchedWithdrawalsRoot,
    SyscallRevert,
};

pub const GAS_PER_BLOB = 131_072;
pub const HISTORY_CONTRACT: u256 = 0x0000F90827F1C53a10cb7A02335B175320002935;
pub const HISTORY_SERVE_WINDOW: u64 = 8192;
const BEACON_ROOTS_ADDRESS: u256 = 0x000F3df6D732807Ef1319fB7B8bB8522d0Beac02;
const HISTORICAL_ROOTS_MODULUS: u256 = 8191;
const SYSTEM_ADDRESS: u160 = 0xfffffffffffffffffffffffffffffffffffffffe;
const DEPOSIT_CONTRACT: u160 = 0x00000000219ab540356cBB839Cbe05303d7705Fa;
const WITHDRAWAL_REQUEST_PREDEPLOY_ADDRESS: u160 = 0x00000961ef480eb55e80d19ad83579a64c007002;
const CONSOLIDATION_REQUEST_PREDEPLOY_ADDRESS: u160 = 0x0000bbddc7ce488642fb579f8b00f3a590007251;
const SYSTEM_CALL_GAS: i32 = 30_000_000;
const DEPOSIT_EVENT_TOPIC: u256 = 0x649bbc62d0e31342afea4e5cd82d4049e7e1ee912fc0889aa790803be39038c5;

pub const PreprocessedBlock = struct {
    block: types.Block,
    rlp_size: usize,
};

pub fn processBlock(
    gpa: std.mem.Allocator,
    logs_allocator: std.mem.Allocator,
    comptime spec: ChainSpec,
    p_block: *const PreprocessedBlock,
    parent: *const types.BlockHeader,
    ancestors: [256]u256,
    state: *State,
) !void {
    try validateBlock(spec, p_block, parent);

    var senders = try gpa.alloc(u160, p_block.block.transactions.len);
    var hashes = try gpa.alloc([32]u8, p_block.block.transactions.len);
    for (p_block.block.transactions, 0..) |bt, index| {
        hashes[index] = try bt.signingHash(gpa, spec.chain_id);
        switch (bt) {
            inline else => |t| senders[index] = try ecrecover(hashes[index], bt.recoveryId(), t.r, t.s),
        }
    }

    try applyEip4788(&p_block.block.header, state);
    try applyEip2935(&p_block.block.header, state);

    var logs: std.DoublyLinkedList = .{};
    defer freeLogs(&logs, logs_allocator);
    const num_logs_per_tx = try gpa.alloc(usize, p_block.block.transactions.len);
    defer gpa.free(num_logs_per_tx);
    var gas_remaining = p_block.block.header.gas_limit;
    var context = contextFromBlock(spec, &p_block.block, ancestors);

    const evm_spec = comptime EvmSpec.specByFork(spec.fork);
    var vm = try evm.EVM.init(gpa, logs_allocator, &logs, &context, evm_spec.evmCapacities());

    for (p_block.block.transactions, 0..) |*tx, index| {
        const msg = try messageFromTx(gpa, tx, senders[index]);
        if (msg.gas_limit > gas_remaining) return Errors.InsufficientGas;

        const gas_used = try vm.process(.{ .fork = evm_spec }, &msg, state);
        gas_remaining -= @intCast(gas_used);
        const blobs_used = switch (tx.*) {
            .blob => |t| t.blob_hashes.len,
            else => 0,
        };
        context.max_blobs_per_block -= blobs_used;
        num_logs_per_tx[index] = vm.num_logs;
        try clearSelfdestructed(gpa, &vm, state);

        state.clearTxState();
        vm.reset();
    }

    if (p_block.block.header.gas_used != p_block.block.header.gas_limit - gas_remaining) return Errors.MismatchedGasUsed;
    if (!std.mem.eql(u8, &p_block.block.header.logs_bloom, &computeLogsBloom(&logs))) return Errors.MismatchedLogsBloom;

    const withdrawals_root = try computeWithdrawalsRoot(gpa, &p_block.block);
    if (!std.mem.eql(u8, &withdrawals_root, &p_block.block.header.withdrawals_root)) return Errors.MismatchedWithdrawalsRoot;
    try applyWithdrawals(&p_block.block, state);

    const requests_hash = try computeRequestsHash(&vm, spec, state, &logs);
    if (!std.mem.eql(u8, &requests_hash, &p_block.block.header.requests_hash)) return Errors.MismatchedRequestsHash;
}

fn computeRequestsHash(
    vm: *evm.EVM,
    comptime spec: ChainSpec,
    state: *State,
    logs: *const std.DoublyLinkedList,
) Errors![32]u8 {
    var outer = Sha256.init(.{});
    try hashDepositRequests(logs, &outer);

    var dummy_logs: std.DoublyLinkedList = .{};
    vm.logs = &dummy_logs;

    vm.reset();
    try hashSystemCall(vm, spec, WITHDRAWAL_REQUEST_PREDEPLOY_ADDRESS, 0x01, state, &outer);
    vm.reset();
    try hashSystemCall(vm, spec, CONSOLIDATION_REQUEST_PREDEPLOY_ADDRESS, 0x02, state, &outer);

    return outer.finalResult();
}

fn hashDepositRequests(logs: *const std.DoublyLinkedList, outer: *Sha256) Errors!void {
    var inner = Sha256.init(.{});
    var count: usize = 0;
    inner.update(&[_]u8{0x00});
    var node = logs.first;
    while (node) |n| {
        const ln: *const evm.EVM.LogNode = @alignCast(@fieldParentPtr("node", n));
        if (ln.log.address == DEPOSIT_CONTRACT and
            ln.log.topics.len > 0 and ln.log.topics[0] == DEPOSIT_EVENT_TOPIC)
        {
            if (!hashDepositLog(&inner, ln.log.data)) return Errors.MismatchedRequestsHash;
            count += 1;
        }
        node = n.next;
    }
    if (count > 0) outer.update(&inner.finalResult());
}

fn hashDepositLog(inner: *Sha256, data: []const u8) bool {
    if (data.len < 576) return false;
    const field_sizes = [_]usize{ 48, 32, 8, 96, 8 };
    var fields: [5][]const u8 = undefined;
    for (field_sizes, 0..) |size, i| {
        const off = std.math.cast(usize, std.mem.readInt(u256, data[i * 32 ..][0..32], .big)) orelse return false;
        if (off + 32 + size > data.len) return false;
        const length = std.math.cast(usize, std.mem.readInt(u256, data[off..][0..32], .big)) orelse return false;
        if (length != size) return false;
        fields[i] = data[off + 32 .. off + 32 + size];
    }
    for (fields) |f| inner.update(f);
    return true;
}

fn hashSystemCall(
    vm: *evm.EVM,
    comptime spec: ChainSpec,
    target: u160,
    type_byte: u8,
    state: *State,
    outer: *Sha256,
) !void {
    const calldata: []u8 = &.{};
    _, const call_err = vm.call(.{
        .fork = EvmSpec.specByFork(spec.fork),
    }, state, SYSTEM_ADDRESS, target, target, SYSTEM_CALL_GAS, calldata, 0, 0, &.{}, true, false) catch return;
    if (call_err) |_| return Errors.SyscallRevert;
    const ret = vm.return_buffer[0..vm.return_data_size];
    if (ret.len > 0) {
        var inner = Sha256.init(.{});
        inner.update(&[_]u8{type_byte});
        inner.update(ret);
        outer.update(&inner.finalResult());
    }
}

fn computeWithdrawalsRoot(gpa: std.mem.Allocator, block: *const types.Block) ![32]u8 {
    const n = block.withdrawals.len;
    if (n == 0) return empty_root_hash;
    const fba_buf = try gpa.alloc(u8, 1024 * 1024);
    defer gpa.free(fba_buf);
    var fba = std.heap.FixedBufferAllocator.init(fba_buf);
    var trie = try Trie.init(&fba);
    defer trie.deinit();

    // Insert in nibble-sorted key order
    const ranges = [3][2]usize{ .{ 1, @min(0x80, n) }, .{ 0, @min(1, n) }, .{ 0x80, n } };
    for (ranges) |range| {
        var i = range[0];
        while (i < range[1]) : (i += 1) {
            var key_list = std.array_list.Managed(u8).init(fba.allocator());
            try rlp.serialize(usize, fba.allocator(), i, &key_list);
            var val_list = std.array_list.Managed(u8).init(fba.allocator());
            try rlp.serialize(types.Withdrawal, fba.allocator(), block.withdrawals[i], &val_list);
            try trie.put(key_list.items, val_list.items);
        }
    }
    return trie.rootHash();
}

fn applyWithdrawals(block: *const types.Block, state: *State) !void {
    for (block.withdrawals) |w| {
        const addr = std.mem.readInt(u160, &w.address, .big);
        (try state.accounts.update(addr)).balance += @as(u256, w.amount) * 1_000_000_000;
    }
}

fn clearSelfdestructed(gpa: std.mem.Allocator, vm: *evm.EVM, state: *State) !void {
    var any = false;
    var it = vm.created_accounts.dirties.iterator();
    while (it.next()) |entry| {
        if (entry.value_ptr.* == .Selfdestructed) {
            state.clearAccount(entry.key_ptr.*);
            any = true;
        }
    }
    if (!any) return;

    var to_remove: std.ArrayListUnmanaged(types.StorageLookup) = .empty;
    defer to_remove.deinit(gpa);
    var slots = state.contract_state.dirties.iterator();
    while (slots.next()) |entry| {
        const addr: u160 = @truncate(entry.key_ptr.address);
        if (vm.created_accounts.dirties.get(addr)) |lc| {
            if (lc == .Selfdestructed) try to_remove.append(gpa, entry.key_ptr.*);
        }
    }
    for (to_remove.items) |k| _ = state.contract_state.dirties.remove(k);
}

fn freeLogs(logs: *std.DoublyLinkedList, allocator: std.mem.Allocator) void {
    while (logs.pop()) |node| {
        const ln: *evm.EVM.LogNode = @alignCast(@fieldParentPtr("node", node));
        allocator.free(ln.log.data);
        allocator.free(ln.log.topics);
        allocator.destroy(ln);
    }
}

pub fn validateBlock(comptime spec: ChainSpec, p_block: *const PreprocessedBlock, parent: *const types.BlockHeader) Errors!void {
    const block = p_block.block;

    if (p_block.rlp_size > spec.max_rlp_size) return Errors.BlockRlpTooBig;
    if (block.header.number != parent.number + 1) return Errors.InvalidBlockNumber;
    if (block.header.timestamp <= parent.timestamp) return Errors.InvalidTimestamp;
    if (block.header.extra_data.len > 32) return Errors.ExtraDataTooLong;
    if (block.header.gas_used > block.header.gas_limit) return Errors.GasLimitExceeded;
    if (block.header.blob_gas_used % GAS_PER_BLOB != 0) return Errors.InvalidBlobGasUsed;
    var expected_blob_gas_used: u64 = 0;
    for (block.transactions) |tx| {
        const blobs = switch (tx) {
            .blob => |t| t.blob_hashes.len,
            else => 0,
        };
        expected_blob_gas_used += blobs * GAS_PER_BLOB;
    }
    if (block.header.blob_gas_used != expected_blob_gas_used) return Errors.MismatchedBlobGasUsed;
    if (block.header.difficulty != 0) return Errors.InvalidDifficulty;
    if (!std.mem.eql(u8, &block.header.nonce, &[_]u8{0} ** 8)) return Errors.InvalidNonce;
    if (block.uncles.len != 0) return Errors.InvalidUncles;

    const max_delta = parent.gas_limit / spec.gas_limit_adjustment_factor;
    if (block.header.gas_limit >= parent.gas_limit + max_delta) return Errors.GasLimitTooHigh;
    if (block.header.gas_limit <= parent.gas_limit - max_delta) return Errors.GasLimitTooLow;
    if (block.header.gas_limit < spec.min_gas_limit) return Errors.GasLimitLessThanMinimum;

    const parent_gas_target = parent.gas_limit / spec.base_fee_elasticity_multiplier;
    var expected_base_fee_per_gas = parent.base_fee_per_gas;
    if (parent.gas_used > parent_gas_target) {
        const delta = parent.gas_used - parent_gas_target;
        const base_fee_per_gas_delta = @max(@as(u128, parent.base_fee_per_gas) * delta / parent_gas_target / spec.base_fee_max_change_denominator, 1);
        expected_base_fee_per_gas += @intCast(base_fee_per_gas_delta);
    } else if (parent.gas_used < parent_gas_target) {
        const delta = parent_gas_target - parent.gas_used;
        const base_fee_per_gas_delta = @as(u128, parent.base_fee_per_gas) * delta / parent_gas_target / spec.base_fee_max_change_denominator;
        expected_base_fee_per_gas -= @intCast(base_fee_per_gas_delta);
    }
    if (expected_base_fee_per_gas != block.header.base_fee_per_gas) return Errors.InvalidBaseFee;

    if (p_block.block.header.excess_blob_gas != calcExcessBlobGas(spec, parent)) return Errors.MismatchedExcessBlobGas;
}

pub fn contextFromBlock(
    comptime spec: ChainSpec,
    block: *const types.Block,
    ancestors: [256]u256,
) evm.Context {
    const h = &block.header;
    return .{
        .chainid = spec.chain_id,
        .number = h.number,
        .coinbase = std.mem.readInt(u160, &h.beneficiary, .big),
        .time = h.timestamp,
        .random = std.mem.readInt(u256, &h.mix_hash, .big),
        .basefee = h.base_fee_per_gas,
        .gas_limit = h.gas_limit,
        .blob_base_fee = blobBaseFee(h.excess_blob_gas, spec.blob_base_fee_update_fraction),
        .max_blobs_per_block = spec.max_blobs_per_block,
        .ancestors = ancestors,
    };
}

pub fn messageFromTx(
    allocator: std.mem.Allocator,
    tx: *types.Transaction,
    sender: u160,
) !evm.Message {
    return .{ .caller = sender, .nonce = switch (tx.*) {
        inline else => |*t| t.nonce,
    }, .target = if (switch (tx.*) {
        inline else => |*t| t.to,
    }) |to| std.mem.readInt(u160, &to, .big) else null, .gas_limit = switch (tx.*) {
        inline else => |*t| @intCast(t.gas_limit),
    }, .gas_price = switch (tx.*) {
        inline .access_list, .legacy => |*t| t.gas_price,
        else => null,
    }, .calldata = switch (tx.*) {
        inline else => |*t| @constCast(t.data),
    }, .value = switch (tx.*) {
        inline else => |*t| t.value,
    }, .access_list = switch (tx.*) {
        .legacy => &.{},
        inline else => |*t| try convertAccessList(allocator, t.access_list),
    }, .max_fee_per_gas = switch (tx.*) {
        .legacy, .access_list => null,
        inline else => |*t| t.gas_price,
    }, .max_priority_fee_per_gas = switch (tx.*) {
        .legacy, .access_list => null,
        inline else => |*t| t.gas_priority_fee,
    }, .authorization_list = switch (tx.*) {
        .set_code => |*t| try convertAuthList(allocator, t.auth_list),
        else => null,
    }, .blob_versioned_hashes = switch (tx.*) {
        .blob => |*t| try convertBlobHashes(allocator, t.blob_hashes),
        else => &.{},
    }, .max_fee_per_blob_gas = switch (tx.*) {
        .blob => |*t| t.max_fee_per_blob_gas,
        else => null,
    } };
}

fn convertBlobHashes(
    allocator: std.mem.Allocator,
    hashes: [][32]u8,
) ![]u256 {
    const blob_hashes = try allocator.alloc(u256, hashes.len);
    for (hashes, blob_hashes) |src, *dst| dst.* = std.mem.readInt(u256, &src, .big);
    return blob_hashes;
}

fn convertAccessList(allocator: std.mem.Allocator, al: []const types.AccessListEntry) ![]evm.AccessListEntry {
    const result = try allocator.alloc(evm.AccessListEntry, al.len);
    for (al, result) |src, *dst| {
        const keys = try allocator.alloc(u256, src.storage_keys.len);
        for (src.storage_keys, keys) |k, *out| out.* = std.mem.readInt(u256, &k, .big);
        dst.* = .{
            .address = std.mem.readInt(u160, &src.address, .big),
            .storage_keys = keys,
        };
    }
    return result;
}

fn convertAuthList(allocator: std.mem.Allocator, auth_list: []const types.AuthorizationTuple) ![]evm.Authorization {
    const result = try allocator.alloc(evm.Authorization, auth_list.len);
    for (auth_list, result) |src, *dst| {
        dst.* = .{
            .chain_id = if (src.chain_id > std.math.maxInt(u64)) std.math.maxInt(u64) else @intCast(src.chain_id),
            .address = std.mem.readInt(u160, &src.address, .big),
            .nonce = src.nonce,
            .authority = recoverEip7702Authority(allocator, src) catch 0,
        };
    }
    return result;
}

fn recoverEip7702Authority(allocator: std.mem.Allocator, auth: types.AuthorizationTuple) !u160 {
    var encoded = std.array_list.Managed(u8).init(allocator);
    defer encoded.deinit();
    const Tuple = struct { chain_id: u256, address: [20]u8, nonce: u64 };
    try rlp.serialize(Tuple, allocator, .{
        .chain_id = auth.chain_id,
        .address = auth.address,
        .nonce = auth.nonce,
    }, &encoded);

    var msg: [257]u8 = undefined;
    msg[0] = 0x05;
    @memcpy(msg[1..][0..encoded.items.len], encoded.items);
    var hash: [32]u8 = undefined;
    Keccak256.hash(msg[0 .. 1 + encoded.items.len], &hash, .{});

    return ecrecover(hash, auth.v, auth.r, auth.s);
}

pub fn computeLogsBloom(logs: *const std.DoublyLinkedList) [256]u8 {
    var bloom = [_]u8{0} ** 256;
    var node = logs.first;
    while (node) |n| {
        const ln: *const evm.EVM.LogNode = @alignCast(@fieldParentPtr("node", n));
        var addr_bytes: [20]u8 = undefined;
        std.mem.writeInt(u160, &addr_bytes, ln.log.address, .big);
        bloomAdd(&bloom, &addr_bytes);
        for (ln.log.topics) |topic| {
            var topic_bytes: [32]u8 = undefined;
            std.mem.writeInt(u256, &topic_bytes, topic, .big);
            bloomAdd(&bloom, &topic_bytes);
        }
        node = n.next;
    }
    return bloom;
}

fn bloomAdd(bloom: *[256]u8, item: []const u8) void {
    var hash: [32]u8 = undefined;
    Keccak256.hash(item, &hash, .{});
    for (0..3) |i| {
        const bit: u11 = @truncate(std.mem.readInt(u16, hash[2 * i ..][0..2], .big));
        bloom[255 - bit / 8] |= @as(u8, 1) << @intCast(bit % 8);
    }
}

fn applyEip4788(header: *const types.BlockHeader, state: *State) !void {
    const timestamp: u256 = header.timestamp;
    const root: u256 = std.mem.readInt(u256, &header.parent_beacon_block_root, .big);
    const idx = timestamp % HISTORICAL_ROOTS_MODULUS;
    _ = try state.contract_state.write(.{ .address = BEACON_ROOTS_ADDRESS, .slot = idx }, timestamp);
    _ = try state.contract_state.write(.{ .address = BEACON_ROOTS_ADDRESS, .slot = idx + HISTORICAL_ROOTS_MODULUS }, root);
}

fn applyEip2935(header: *const types.BlockHeader, state: *State) !void {
    const slot: u256 = (header.number - 1) % HISTORY_SERVE_WINDOW;
    const value: u256 = std.mem.readInt(u256, &header.parent_hash, .big);
    _ = try state.contract_state.write(.{ .address = HISTORY_CONTRACT, .slot = slot }, value);
}

fn calcExcessBlobGas(comptime spec: ChainSpec, parent: *const types.BlockHeader) u64 {
    const excess_blob_gas = parent.excess_blob_gas + parent.blob_gas_used;
    const target_gas = spec.target_blobs_per_block * GAS_PER_BLOB;

    if (excess_blob_gas < target_gas) return 0;

    const reserve_price = @as(u128, spec.blobs_base_cost) * parent.base_fee_per_gas;
    const blob_price = blobBaseFee(parent.excess_blob_gas, spec.blob_base_fee_update_fraction) * GAS_PER_BLOB;
    if (reserve_price > blob_price) {
        const scaled_excess = parent.blob_gas_used * (spec.max_blobs_per_block - spec.target_blobs_per_block) / spec.max_blobs_per_block;
        return parent.excess_blob_gas + scaled_excess;
    }

    return excess_blob_gas - target_gas;
}
