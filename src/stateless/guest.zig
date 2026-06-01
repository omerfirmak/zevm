const std = @import("std");
const ssz = @import("ssz");
const rlp = @import("rlp");
const zevm = @import("zevm");
const types = @import("types.zig");
const CommittedState = @import("committed_state").CommittedState;

const STATELESS_INPUT_SCHEMA_ID: u16 = 0x0001;
const STATELESS_INPUT_SCHEMA_ID_SIZE: usize = 2;

pub fn verify_ssz(allocator: std.mem.Allocator, input_bytes: []const u8) ![]const u8 {
    if (input_bytes.len < STATELESS_INPUT_SCHEMA_ID_SIZE) return error.UnsupportedSchemaId;
    const schema_id = std.mem.readInt(u16, input_bytes[0..STATELESS_INPUT_SCHEMA_ID_SIZE], .big);
    if (schema_id != STATELESS_INPUT_SCHEMA_ID) return error.UnsupportedSchemaId;

    var input: types.StatelessInput = undefined;
    try ssz.deserialize(types.StatelessInput, input_bytes[STATELESS_INPUT_SCHEMA_ID_SIZE..], &input, allocator);

    const res = try verify(allocator, input);

    var buf: std.ArrayList(u8) = .empty;
    try ssz.serialize(types.StatelessValidationResult, res, &buf, allocator);
    return buf.items;
}

pub fn verify(allocator: std.mem.Allocator, input: types.StatelessInput) !types.StatelessValidationResult {
    var headers = try allocator.alloc(zevm.types.BlockHeader, input.witness.headers.len);
    var ancestors = try allocator.alloc([32]u8, input.witness.headers.len);
    for (input.witness.headers, 0..) |header_bytes, i| {
        std.crypto.hash.sha3.Keccak256.hash(header_bytes, &ancestors[i], .{});
        _ = try rlp.deserialize(zevm.types.BlockHeader, allocator, header_bytes, &headers[i]);
        if (i > 0 and !std.mem.eql(u8, &ancestors[i], &headers[i].parent_hash)) {
            return error.InvalidAncestors;
        }
    }

    const parent = &headers[headers.len - 1];
    const block = try makeBlock(allocator, &input.new_payload_request, input.public_keys);
    _ = try CommittedState.init(allocator, parent.*.state_root, input.witness.state, input.witness.codes, &block.bal.?);
    return error.NotImplemented;
}

fn makeBlock(
    allocator: std.mem.Allocator,
    request: *const types.NewPayloadRequest,
    public_keys: [][65]u8,
) !zevm.processor.PreprocessedBlock {
    const payload = &request.execution_payload;

    const txs = try allocator.alloc(zevm.types.Transaction, payload.transactions.len);
    const raw_txs = try allocator.alloc(rlp.RawValue, payload.transactions.len);
    defer allocator.free(raw_txs);
    for (payload.transactions, 0..) |raw, i| {
        _ = try txs[i].decodeFromRLP(allocator, raw);
        raw_txs[i] = .{ .value = raw };
    }

    const senders = try allocator.alloc(u160, payload.transactions.len);
    for (public_keys, 0..) |pk, i| senders[i] = zevm.curve.addressFromPubkey(pk);

    const withdrawals = try allocator.alloc(zevm.types.Withdrawal, payload.withdrawals.len);
    for (payload.withdrawals, withdrawals) |src, *dst| {
        dst.* = .{
            .index = src.index,
            .validator_index = src.validator_index,
            .address = src.address,
            .amount = src.amount,
        };
    }

    if (payload.base_fee_per_gas > std.math.maxInt(u64)) return error.BaseFeeTooLarge;

    var bal: zevm.types.BlockAccessLists = undefined;
    _ = try rlp.deserialize(zevm.types.BlockAccessLists, allocator, request.execution_payload.block_access_list, &bal);
    var bal_hash: [32]u8 = undefined;
    std.crypto.hash.sha3.Keccak256.hash(request.execution_payload.block_access_list, &bal_hash, .{});

    const header = zevm.types.BlockHeader{
        .parent_hash = payload.parent_hash,
        .ommers_hash = zevm.types.empty_ommers_hash,
        .beneficiary = payload.fee_recipient,
        .state_root = payload.state_root,
        .transactions_root = try zevm.processor.computeRoot(rlp.RawValue, allocator, raw_txs),
        .receipts_root = payload.receipts_root,
        .logs_bloom = payload.logs_bloom,
        .difficulty = 0, // post-merge: always 0
        .number = payload.block_number,
        .gas_limit = payload.gas_limit,
        .gas_used = payload.gas_used,
        .timestamp = payload.timestamp,
        .extra_data = payload.extra_data,
        .mix_hash = payload.prev_randao,
        .nonce = [_]u8{0} ** 8, // post-merge: always zero
        .base_fee_per_gas = @intCast(payload.base_fee_per_gas),
        .withdrawals_root = std.mem.zeroes([32]u8),
        .blob_gas_used = payload.blob_gas_used,
        .excess_blob_gas = payload.excess_blob_gas,
        .parent_beacon_block_root = request.parent_beacon_block_root,
        .requests_hash = std.mem.zeroes([32]u8),
        .block_access_list_hash = bal_hash,
        .slot_number = payload.slot_number,
    };

    const block: zevm.types.Block = .{
        .header = header,
        .transactions = txs,
        .uncles = &.{},
        .withdrawals = withdrawals,
    };

    var encoded = std.array_list.Managed(u8).init(allocator);
    defer encoded.deinit();
    try rlp.serialize(zevm.types.Block, allocator, block, &encoded);

    return zevm.processor.PreprocessedBlock{
        .block = block,
        .rlp_size = encoded.items.len,
        .bal = bal,
        .senders = senders,
    };
}
