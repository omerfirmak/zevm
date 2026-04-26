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
const blobBaseFee = @import("../blob_fee.zig").blobBaseFee;

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
} || evm.Errors || std.mem.Allocator.Error;

pub const GAS_PER_BLOB = 131_072;
pub const HISTORY_CONTRACT: u256 = 0x0000F90827F1C53a10cb7A02335B175320002935;
pub const HISTORY_SERVE_WINDOW: u64 = 8192;

pub const PreprocessedBlock = struct {
    block: types.Block,
    rlp_size: usize,
    txhashes: []const [32]u8,
    senders: []const u160,
};

pub fn processBlock(
    gpa: std.mem.Allocator,
    logs_allocator: std.mem.Allocator,
    comptime spec: ChainSpec,
    p_block: *const PreprocessedBlock,
    parent: *const types.BlockHeader,
    ancestors: [256]u256,
    state: *State,
) Errors!void {
    try validateBlock(spec, p_block, parent);
    try applyEip2935(&p_block.block.header, state);

    var logs: std.DoublyLinkedList = .{};
    var num_logs_per_tx = try gpa.alloc(usize, p_block.block.transactions.len);
    var gas_remaining = p_block.block.header.gas_limit;
    var blob_gas_used: u64 = 0;
    const context = contextFromBlock(spec, &p_block.block, ancestors);
    for (p_block.block.transactions, 0..) |*tx, index| {
        const msg = try messageFromTx(gpa, tx, p_block.senders[index]);
        if (msg.gas_limit > gas_remaining) return Errors.InsufficientGas;

        var vm = try evm.EVM.init(gpa, logs_allocator, &logs, &msg, &context);
        const gas_used = try vm.process(.{ .fork = EvmSpec.specByFork(spec.fork) }, state);
        gas_remaining -= @intCast(gas_used);
        blob_gas_used += switch (tx.*) {
            .blob => |t| t.blob_hashes.len * GAS_PER_BLOB,
            else => 0,
        };
        num_logs_per_tx[index] = vm.num_logs;
    }

    if (p_block.block.header.gas_used != p_block.block.header.gas_limit - gas_remaining) return Errors.MismatchedGasUsed;
    if (p_block.block.header.blob_gas_used != blob_gas_used) return Errors.MismatchedBlobGasUsed;
    if (!std.mem.eql(u8, &p_block.block.header.logs_bloom, &computeLogsBloom(&logs))) return Errors.MismatchedLogsBloom;
}

pub fn validateBlock(comptime spec: ChainSpec, p_block: *const PreprocessedBlock, parent: *const types.BlockHeader) Errors!void {
    const block = p_block.block;

    if (p_block.rlp_size > spec.max_rlp_size) return Errors.BlockRlpTooBig;
    if (block.header.number != parent.number + 1) return Errors.InvalidBlockNumber;
    if (block.header.timestamp <= parent.timestamp) return Errors.InvalidTimestamp;
    if (block.header.extra_data.len > 32) return Errors.ExtraDataTooLong;
    if (block.header.gas_used > block.header.gas_limit) return Errors.GasLimitExceeded;
    if (block.header.blob_gas_used > spec.max_blobs_per_block * GAS_PER_BLOB) return Errors.InvalidBlobGasUsed;
    if (block.header.blob_gas_used % GAS_PER_BLOB != 0) return Errors.InvalidBlobGasUsed;
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
            .authority = recoverEip7702Authority(src),
        };
    }
    return result;
}

fn recoverEip7702Authority(auth: types.AuthorizationTuple) u160 {
    var stack_buf: [256]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&stack_buf);
    var encoded = std.array_list.Managed(u8).init(fba.allocator());
    const Tuple = struct { chain_id: u256, address: [20]u8, nonce: u64 };
    rlp.serialize(Tuple, fba.allocator(), .{
        .chain_id = auth.chain_id,
        .address = auth.address,
        .nonce = auth.nonce,
    }, &encoded) catch return 0;

    var msg: [257]u8 = undefined;
    msg[0] = 0x05;
    @memcpy(msg[1..][0..encoded.items.len], encoded.items);
    var hash: [32]u8 = undefined;
    Keccak256.hash(msg[0 .. 1 + encoded.items.len], &hash, .{});

    const curve = secp256k1.Secp256k1.init() catch return 0;
    var sig: secp256k1.Signature = [_]u8{0} ** 65;
    std.mem.writeInt(u256, sig[0..32], auth.r, .big);
    std.mem.writeInt(u256, sig[32..64], auth.s, .big);
    sig[64] = @intCast(auth.v & 1);
    const pubkey = curve.recoverPubkey(hash, sig) catch return 0;

    var pubkey_hash: [32]u8 = undefined;
    Keccak256.hash(pubkey[1..65], &pubkey_hash, .{});
    return std.mem.readInt(u160, pubkey_hash[12..32], .big);
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
        const bit: u11 = @truncate(std.mem.readInt(u16, hash[2 * i ..][0..2], .little));
        bloom[255 - bit / 8] |= @as(u8, 1) << @intCast(bit % 8);
    }
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

    const reserve_price = spec.blobs_base_cost * parent.base_fee_per_gas;
    const blob_price = blobBaseFee(parent.excess_blob_gas, spec.blob_base_fee_update_fraction);
    if (reserve_price > blob_price) {
        const scaled_excess = parent.blob_gas_used * (spec.max_blobs_per_block - spec.target_blobs_per_block) / spec.max_blobs_per_block;
        return parent.excess_blob_gas + scaled_excess;
    }

    return excess_blob_gas - target_gas;
}

test {
    std.testing.refAllDecls(@This());
}
