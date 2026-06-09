const std = @import("std");
const ssz = @import("ssz");
const rlp = @import("rlp");
const zevm = @import("zevm");
const types = @import("types.zig");
const CommittedState = @import("committed_state").CommittedState;
const Spec = zevm.spec.Spec;

const STATELESS_INPUT_SCHEMA_ID: u16 = 0x0001;
const STATELESS_INPUT_SCHEMA_ID_SIZE: usize = 2;

pub fn verify_ssz(allocator: std.mem.Allocator, input_bytes: []const u8) ![]const u8 {
    if (input_bytes.len < STATELESS_INPUT_SCHEMA_ID_SIZE) return error.UnsupportedSchemaId;
    const schema_id = std.mem.readInt(u16, input_bytes[0..STATELESS_INPUT_SCHEMA_ID_SIZE], .big);
    if (schema_id != STATELESS_INPUT_SCHEMA_ID) return error.UnsupportedSchemaId;

    var input: types.StatelessInput = undefined;
    try ssz.deserialize(types.StatelessInput, input_bytes[STATELESS_INPUT_SCHEMA_ID_SIZE..], &input, allocator);

    var res: types.StatelessValidationResult = .{
        .chain_config = input.chain_config,
        .new_payload_request_root = @splat(0),
        .successful_validation = true,
    };
    verify(allocator, input) catch {
        res.successful_validation = false;
    };

    var buf: std.ArrayList(u8) = .empty;
    try ssz.serialize(types.StatelessValidationResult, res, &buf, allocator);
    return buf.items;
}

pub fn verify(allocator: std.mem.Allocator, input: types.StatelessInput) !void {
    const spec = zevm.spec.Amsterdam;
    const headers = try allocator.alloc(zevm.types.BlockHeader, input.witness.headers.len);
    const header_hashes = try allocator.alloc([32]u8, input.witness.headers.len);
    for (input.witness.headers, 0..) |header_bytes, i| {
        std.crypto.hash.sha3.Keccak256.hash(header_bytes, &header_hashes[i], .{});
        _ = try rlp.deserialize(zevm.types.BlockHeader, allocator, header_bytes, &headers[i]);
        if (i > 0 and !std.mem.eql(u8, &header_hashes[i - 1], &headers[i].parent_hash)) {
            return error.InvalidAncestors;
        }
    }

    if (headers.len == 0) return error.MissingParentHeader;
    const parent = &headers[headers.len - 1];
    var block = try makeBlock(allocator, &input.new_payload_request, input.public_keys);

    var ancestors: [256]u256 = @splat(0);
    const n = @min(header_hashes.len, 256);
    for (0..n) |k| {
        ancestors[k] = std.mem.readInt(u256, &header_hashes[header_hashes.len - 1 - k], .big);
    }

    var committed = try CommittedState.init(allocator, parent.state_root, input.witness.state, input.witness.codes, &block.bal.?);
    var state = try zevm.state.State.init(
        allocator,
        &committed,
        stateCapacities(spec, block.bal.?, block.block.header.gas_used),
    );

    // processBlock doesn't touch the code of these contracts, assert they exist in the witness here
    try assertAccountCodeIsInWitness(&committed, zevm.processor.HISTORY_CONTRACT);
    try assertAccountCodeIsInWitness(&committed, zevm.processor.BEACON_ROOTS_ADDRESS);

    try zevm.processor.processBlock(
        allocator,
        zevm.chainspec.chainSpecByFork(spec.fork),
        &block,
        parent,
        ancestors,
        &state,
    );
}

fn assertAccountCodeIsInWitness(committed: *const CommittedState, addr: u160) !void {
    const acc = try committed.account(addr);
    _ = try committed.code(acc.code_hash);
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

    var encoded = std.array_list.Managed(u8).init(allocator);
    defer encoded.deinit();
    try rlp.serialize(struct {
        header: zevm.types.BlockHeader,
        transactions: []rlp.RawValue,
        uncles: []zevm.types.BlockHeader,
        withdrawals: []zevm.types.Withdrawal,
    }, allocator, .{
        .header = header,
        .transactions = raw_txs,
        .uncles = &.{},
        .withdrawals = withdrawals,
    }, &encoded);

    return zevm.processor.PreprocessedBlock{
        .block = .{
            .header = header,
            .transactions = txs,
            .uncles = &.{},
            .withdrawals = withdrawals,
        },
        .rlp_size = encoded.items.len,
        .bal = bal,
        .senders = senders,
    };
}

fn stateCapacities(comptime spec: Spec, bal: zevm.types.BlockAccessLists, gas_limit: u64) Spec.StateCapacities {
    var caps = spec.stateCapacities(gas_limit);

    var slots_num: usize = 0;
    for (bal) |acc| {
        slots_num += acc.storage_reads.len + acc.storage_changes.len;
    }

    caps.contract_dirties = @intCast(slots_num + 128);
    caps.account_dirties = @intCast(bal.len + 16);
    return caps;
}
