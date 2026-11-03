// Copyright (c) 2025-2026 zevm authors
// SPDX-License-Identifier: MIT OR Apache-2.0

const std = @import("std");
const types = @import("../types.zig");
const rlp = @import("rlp");
const processor = @import("../processor/processor.zig");
const crypto = @import("../evm/crypto/hash.zig");

const CommittedState = @import("../evm/committed_state.zig").CommittedState;

pub const PayloadStatus = struct {
    pub const Status = enum { valid, invalid, syncing, accepted };

    status: Status,
    latest_valid_hash: ?[32]u8 = null,
    validation_error: ?anyerror = null,
};

pub const ForkchoiceState = struct {
    head_block_hash: [32]u8,
    safe_block_hash: [32]u8,
    finalized_block_hash: [32]u8,
};

pub const Engine = struct {
    const Self = @This();

    pub fn newPayload(
        self: *Self,
        allocator: std.mem.Allocator,
        payload: *const ExecutionPayload,
        versioned_hashes: []const [32]u8,
        parent_beacon_block_root: [32]u8,
        execution_requests: []const []const u8,
    ) !PayloadStatus {
        _ = self;
        _ = allocator;
        _ = payload;
        _ = versioned_hashes;
        _ = parent_beacon_block_root;
        _ = execution_requests;
        return error.NotImplemented;
    }

    pub fn forkchoiceUpdated(
        self: *Self,
        allocator: std.mem.Allocator,
        state: ForkchoiceState,
    ) !PayloadStatus {
        _ = self;
        _ = allocator;
        _ = state;
        return error.NotImplemented;
    }
};

pub const ExecutionPayload = struct {
    parent_hash: [32]u8,
    fee_recipient: [20]u8,
    state_root: [32]u8,
    receipts_root: [32]u8,
    logs_bloom: [256]u8,
    prev_randao: [32]u8,
    block_number: u64,
    gas_limit: u64,
    gas_used: u64,
    timestamp: u64,
    extra_data: []const u8,
    base_fee_per_gas: u256,
    block_hash: [32]u8,
    transactions: []const []const u8,
    withdrawals: []const types.Withdrawal,
    blob_gas_used: u64,
    excess_blob_gas: u64,
    block_access_list: []const u8,
    slot_number: u64,

    pub fn toBlock(
        payload: *const ExecutionPayload,
        allocator: std.mem.Allocator,
        versioned_hashes: []const [32]u8,
        parent_beacon_block_root: [32]u8,
        execution_requests: []const []const u8,
        chain_id: u64,
    ) !processor.PreprocessedBlock {
        if (payload.extra_data.len > 32) return error.ExtraDataTooLong;
        if (payload.base_fee_per_gas > std.math.maxInt(u64)) return error.BaseFeeTooLarge;

        const txs = try allocator.alloc(types.Transaction, payload.transactions.len);
        const raw_txs = try allocator.alloc(rlp.RawValue, payload.transactions.len);
        defer allocator.free(raw_txs);
        const body_txs = try allocator.alloc(rlp.RawValue, payload.transactions.len);
        defer allocator.free(body_txs);
        var n_body_txs: usize = 0;
        defer for (body_txs[0..n_body_txs], raw_txs[0..n_body_txs]) |body, raw| {
            if (body.value.ptr != raw.value.ptr) allocator.free(body.value);
        };
        for (payload.transactions, 0..) |bytes, i| {
            _ = try txs[i].decodeFromRLP(allocator, bytes);
            raw_txs[i] = .{ .value = bytes };
            if (bytes.len > 0 and bytes[0] <= 0x7f) {
                var wrapped = std.array_list.Managed(u8).init(allocator);
                errdefer wrapped.deinit();
                try rlp.serialize([]const u8, allocator, bytes, &wrapped);
                body_txs[i] = .{ .value = try wrapped.toOwnedSlice() };
            } else {
                body_txs[i] = .{ .value = bytes };
            }
            n_body_txs = i + 1;
        }

        const senders = try allocator.alloc(u160, payload.transactions.len);
        for (txs, senders) |*tx, *sender| sender.* = try processor.recoverTxSender(allocator, tx, chain_id);

        const withdrawals = try allocator.dupe(types.Withdrawal, payload.withdrawals);

        var bal: types.BlockAccessLists = undefined;
        _ = try rlp.deserialize(types.BlockAccessLists, allocator, payload.block_access_list, &bal);
        const bal_hash = crypto.keccak256(payload.block_access_list);
        var extra_data: types.ExtraData = undefined;
        @memcpy(extra_data.buf[0..payload.extra_data.len], payload.extra_data);
        extra_data.len = payload.extra_data.len;

        const header = types.BlockHeader{
            .parent_hash = payload.parent_hash,
            .ommers_hash = types.empty_ommers_hash,
            .beneficiary = payload.fee_recipient,
            .state_root = payload.state_root,
            .transactions_root = try processor.computeRoot(rlp.RawValue, allocator, raw_txs),
            .receipts_root = payload.receipts_root,
            .logs_bloom = payload.logs_bloom,
            .difficulty = 0, // post-merge: always 0
            .number = payload.block_number,
            .gas_limit = payload.gas_limit,
            .gas_used = payload.gas_used,
            .timestamp = payload.timestamp,
            .extra_data = extra_data,
            .mix_hash = payload.prev_randao,
            .nonce = @splat(0), // post-merge: always zero
            .base_fee_per_gas = @intCast(payload.base_fee_per_gas),
            .withdrawals_root = try processor.computeRoot(types.Withdrawal, allocator, withdrawals),
            .blob_gas_used = payload.blob_gas_used,
            .excess_blob_gas = payload.excess_blob_gas,
            .parent_beacon_block_root = parent_beacon_block_root,
            .requests_hash = try requestsHash(execution_requests),
            .block_access_list_hash = bal_hash,
            .slot_number = payload.slot_number,
        };

        if (!std.mem.eql(u8, &header.hash(), &payload.block_hash)) return error.InvalidBlockHash;

        var encoded = std.array_list.Managed(u8).init(allocator);
        defer encoded.deinit();
        try rlp.serialize(struct {
            header: types.BlockHeader,
            transactions: []rlp.RawValue,
            uncles: []types.BlockHeader,
            withdrawals: []types.Withdrawal,
        }, allocator, .{
            .header = header,
            .transactions = body_txs,
            .uncles = &.{},
            .withdrawals = withdrawals,
        }, &encoded);

        const block = processor.PreprocessedBlock{
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
        try validateVersionedHashes(&block, versioned_hashes);
        return block;
    }
};

pub fn validateVersionedHashes(
    block: *const processor.PreprocessedBlock,
    declared: []const [32]u8,
) !void {
    var i: usize = 0;
    for (block.block.transactions) |*tx| {
        const hashes = switch (tx.*) {
            .blob => |*t| t.blob_hashes,
            else => continue,
        };
        for (hashes) |*h| {
            if (i >= declared.len or !std.mem.eql(u8, h[0..], declared[i][0..])) {
                return error.InvalidVersionedHashes;
            }
            i += 1;
        }
    }
    if (i != declared.len) return error.InvalidVersionedHashes;
}

pub fn requestsHash(requests: []const []const u8) ![32]u8 {
    var hashes: [256 * 32]u8 = undefined;
    var prev_type: ?u8 = null;
    for (requests, 0..) |r, i| {
        if (r.len <= 1) return error.InvalidExecutionRequests;
        if (prev_type) |p| if (r[0] <= p) return error.InvalidExecutionRequests;
        prev_type = r[0];
        hashes[i * 32 ..][0..32].* = crypto.sha256(r);
    }
    return crypto.sha256(hashes[0 .. requests.len * 32]);
}
