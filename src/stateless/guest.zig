// Copyright (c) 2025-2026 zevm authors
// SPDX-License-Identifier: MIT OR Apache-2.0

const std = @import("std");
const ssz = @import("ssz");
const rlp = @import("rlp");
const zevm = @import("zevm");
const types = @import("types.zig");
const committed_state = @import("committed_state");
const CommittedState = committed_state.CommittedState;
const Spec = zevm.spec.Spec;

const STATELESS_INPUT_SCHEMA_ID: u16 = 0x1501; // 0x15 (Amsterdam) || 0x01 (Rev)
const STATELESS_INPUT_SCHEMA_ID_SIZE: usize = 2;

pub fn verify_ssz(allocator: std.mem.Allocator, input_bytes: []const u8) ![]const u8 {
    @setEvalBranchQuota(200_000);
    var res: types.StatelessValidationResult = .{
        .new_payload_request_root = @splat(0),
        .successful_validation = false,
        .chain_id = 0,
        .schema_id = 0,
    };

    if (input_bytes.len < STATELESS_INPUT_SCHEMA_ID_SIZE)
        return serialize_ssz_result(allocator, res);
    const schema_id = std.mem.readInt(u16, input_bytes[0..STATELESS_INPUT_SCHEMA_ID_SIZE], .big);
    if (schema_id != STATELESS_INPUT_SCHEMA_ID)
        return serialize_ssz_result(allocator, res);

    var input: types.StatelessInput = undefined;
    ssz.deserialize(types.StatelessInput, input_bytes[STATELESS_INPUT_SCHEMA_ID_SIZE..], &input, allocator) catch
        return serialize_ssz_result(allocator, res);

    res.chain_id = input.chain_id;
    res.schema_id = STATELESS_INPUT_SCHEMA_ID;
    ssz.hashTreeRoot(zevm.crypto.hash.Sha256, types.NewPayloadRequest, input.new_payload_request, &res.new_payload_request_root, allocator) catch
        return serialize_ssz_result(allocator, res);

    if (input.chain_id != @import("build_options").chain_id)
        return serialize_ssz_result(allocator, res);

    res.successful_validation = if (verify(allocator, input)) |_| true else |_| false;
    return serialize_ssz_result(allocator, res);
}

fn serialize_ssz_result(allocator: std.mem.Allocator, res: types.StatelessValidationResult) ![]const u8 {
    var buf: std.ArrayList(u8) = .empty;
    try ssz.serialize(types.StatelessValidationResult, res, &buf, allocator);
    return buf.items;
}

pub fn verify(allocator: std.mem.Allocator, input: types.StatelessInput) !void {
    const spec = comptime zevm.processor.Spec.fromFork(.Amsterdam);
    const headers = try allocator.alloc(zevm.types.BlockHeader, input.witness.headers.len());
    const header_hashes = try allocator.alloc([32]u8, input.witness.headers.len());
    for (input.witness.headers.constSlice(), 0..) |*header_bytes, i| {
        header_hashes[i] = zevm.crypto.hash.keccak256(header_bytes.constSlice());
        const consumed = try rlp.deserialize(zevm.types.BlockHeader, allocator, header_bytes.constSlice(), &headers[i]);
        if (consumed != header_bytes.len()) return error.InvalidWitnessHeader;
        if (i > 0 and !std.mem.eql(u8, &header_hashes[i - 1], &headers[i].parent_hash)) {
            return error.InvalidAncestors;
        }
    }

    if (headers.len == 0) return error.MissingParentHeader;
    const parent = &headers[headers.len - 1];
    var block = try makeBlock(allocator, &input.new_payload_request, input.chain_id);

    var committed = try CommittedState.init(allocator, parent.state_root, input.witness.state, input.witness.codes, &block.bal.?, header_hashes, parent.number);
    var state = try zevm.state.State.init(
        allocator,
        &committed,
        stateCapacities(spec.evmSpec(), block.bal.?, input.witness.codes, block.block.transactions, block.block.withdrawals.len, block.block.header.gas_used),
    );

    try zevm.processor.processBlock(
        allocator,
        spec,
        &block,
        parent,
        &state,
    );

    const computed_state_root = try calculateStateRoot(
        allocator,
        &committed.state_trie,
        &committed.account_tries,
        &state,
        &block.bal.?,
    );
    if (!std.mem.eql(u8, &computed_state_root, &block.block.header.state_root)) {
        return error.MismatchedStateRoot;
    }
}

fn assertAccountCodeIsInWitness(committed: *const CommittedState, addr: u160) !void {
    const acc = try committed.account(addr);
    if (std.mem.eql(u8, &acc.code_hash, &zevm.types.empty_code_hash)) return;
    _ = try committed.code(acc.code_hash);
}

fn makeBlock(
    allocator: std.mem.Allocator,
    request: *const types.NewPayloadRequest,
    chain_id: u64,
) !zevm.processor.PreprocessedBlock {
    const p = &request.execution_payload;

    const txs = try allocator.alloc([]const u8, p.transactions.len());
    for (p.transactions.constSlice(), txs) |*raw, *dst| dst.* = raw.constSlice();

    const withdrawals = try allocator.alloc(zevm.types.Withdrawal, p.withdrawals.len());
    for (p.withdrawals.constSlice(), withdrawals) |*src, *dst| {
        dst.* = .{
            .index = src.index,
            .validator_index = src.validator_index,
            .address = src.address,
            .amount = src.amount,
        };
    }

    const payload: zevm.engine.ExecutionPayload = .{
        .parent_hash = p.parent_hash,
        .fee_recipient = p.fee_recipient,
        .state_root = p.state_root,
        .receipts_root = p.receipts_root,
        .logs_bloom = p.logs_bloom,
        .prev_randao = p.prev_randao,
        .block_number = p.block_number,
        .gas_limit = p.gas_limit,
        .gas_used = p.gas_used,
        .timestamp = p.timestamp,
        .extra_data = p.extra_data.constSlice(),
        .base_fee_per_gas = p.base_fee_per_gas,
        .block_hash = p.block_hash,
        .transactions = txs,
        .withdrawals = withdrawals,
        .blob_gas_used = p.blob_gas_used,
        .excess_blob_gas = p.excess_blob_gas,
        .block_access_list = p.block_access_list.constSlice(),
        .slot_number = p.slot_number,
    };

    return payload.toBlock(
        allocator,
        request.versioned_hashes.constSlice(),
        request.parent_beacon_block_root,
        try flattenRequests(allocator, &request.execution_requests),
        chain_id,
    );
}

fn flattenRequests(allocator: std.mem.Allocator, requests: *const types.ExecutionRequests) ![]const []const u8 {
    const fields = .{
        .{ 0x00, "deposits" },
        .{ 0x01, "withdrawals" },
        .{ 0x02, "consolidations" },
        .{ 0x03, "builder_deposits" },
        .{ 0x04, "builder_exits" },
    };
    const out = try allocator.alloc([]const u8, fields.len);
    var n: usize = 0;
    inline for (fields) |entry| {
        const items = @field(requests, entry[1]).constSlice();
        if (items.len > 0) {
            var buf: std.ArrayList(u8) = .empty;
            try buf.append(allocator, entry[0]);
            for (items) |item| try ssz.serialize(@TypeOf(item), item, &buf, allocator);
            out[n] = buf.items;
            n += 1;
        }
    }
    return out[0..n];
}

fn stateCapacities(comptime spec: Spec, bal: zevm.types.BlockAccessLists, codes: anytype, txs: []const zevm.types.Transaction, num_withdrawals: usize, gas_limit: u64) Spec.StateCapacities {
    var caps = spec.stateCapacities(gas_limit);

    var slots_num: usize = 0;
    for (bal) |acc| {
        slots_num += acc.storage_reads.len + acc.storage_changes.len;
    }

    caps.contract_dirties = @intCast(slots_num + 128);
    caps.account_dirties = @intCast(bal.len + 16);
    caps.account_journal = @max(caps.account_journal, caps.account_dirties) + @as(u32, @intCast(num_withdrawals));

    const fn_size = @sizeOf(usize);
    const delegation_code_len = 23; // 3-byte prefix + 20-byte address
    var num_codes: usize = 0;
    var code_bytes: usize = 0;
    for (codes.constSlice()) |*code| {
        num_codes += 1;
        code_bytes += code.constSlice().len;
    }
    for (bal) |acc| {
        for (acc.code_changes) |cc| {
            num_codes += 1;
            code_bytes += cc.code.len;
        }
    }
    for (txs) |tx| {
        if (tx == .set_code) {
            num_codes += tx.set_code.auth_list.len;
            code_bytes += tx.set_code.auth_list.len * delegation_code_len;
        }
    }
    num_codes += gas_limit / spec.create_access;
    code_bytes += gas_limit / spec.cpsb;

    caps.code_slots = @intCast(num_codes + 128);
    caps.bytecode_buf = code_bytes * (1 + fn_size) + num_codes * 512;
    return caps;
}

fn calculateStateRoot(
    allocator: std.mem.Allocator,
    state_trie: *zevm.AccountTrie,
    account_tries: *std.AutoHashMapUnmanaged(u160, zevm.StorageTrie),
    state: *zevm.state.State,
    bal: *const zevm.types.BlockAccessLists,
) ![32]u8 {
    const state_keys = try allocator.alloc([32]u8, bal.len);
    defer allocator.free(state_keys);
    const state_accounts = try allocator.alloc(?zevm.types.Account, bal.len);
    defer allocator.free(state_accounts);

    var n_dirty: usize = 0;
    for (bal.*) |*acc_change_entry| {
        const dirty_storage = acc_change_entry.storage_changes.len != 0;
        const dirty = dirty_storage or
            acc_change_entry.balance_changes.len != 0 or
            acc_change_entry.nonce_changes.len != 0 or
            acc_change_entry.code_changes.len != 0;
        if (!dirty) continue;

        var post_acc = try state.accounts.read(acc_change_entry.addr);

        if (dirty_storage) {
            const storage_trie = account_tries.getPtr(acc_change_entry.addr) orelse return error.MissingStorageTrie;
            const keys = try allocator.alloc([32]u8, acc_change_entry.storage_changes.len);
            defer allocator.free(keys);
            const values = try allocator.alloc(u256, acc_change_entry.storage_changes.len);
            defer allocator.free(values);
            for (acc_change_entry.storage_changes, keys, values) |slot_change, *k, *v| {
                k.* = zevm.types.keccakOfU256(slot_change.key);
                v.* = try state.contract_state.read(.{ .address = acc_change_entry.addr, .slot = slot_change.key });
            }
            zevm.types.sortPairsByHash(u256, keys, values);
            try storage_trie.update(keys, values);
            post_acc.storage_hash = try storage_trie.rootHash();
        }

        state_keys[n_dirty] = zevm.types.keccakOfU160(acc_change_entry.addr);
        state_accounts[n_dirty] = if (post_acc.isEmpty()) null else post_acc;
        n_dirty += 1;
    }

    if (n_dirty > 0) {
        zevm.types.sortPairsByHash(?zevm.types.Account, state_keys[0..n_dirty], state_accounts[0..n_dirty]);
        try state_trie.update(state_keys[0..n_dirty], state_accounts[0..n_dirty]);
    }
    return state_trie.rootHash();
}
