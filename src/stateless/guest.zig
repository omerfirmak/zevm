const std = @import("std");
const ssz = @import("ssz");
const rlp = @import("rlp");
const zevm = @import("zevm");
const types = @import("types.zig");
const committed_state = @import("committed_state");
const CommittedState = committed_state.CommittedState;
const Spec = zevm.spec.Spec;

const STATELESS_INPUT_SCHEMA_ID: u16 = 0x0001;
const STATELESS_INPUT_SCHEMA_ID_SIZE: usize = 2;

pub fn verify_ssz(allocator: std.mem.Allocator, input_bytes: []const u8) ![]const u8 {
    @setEvalBranchQuota(200_000);
    if (input_bytes.len < STATELESS_INPUT_SCHEMA_ID_SIZE) return error.UnsupportedSchemaId;
    const schema_id = std.mem.readInt(u16, input_bytes[0..STATELESS_INPUT_SCHEMA_ID_SIZE], .big);
    if (schema_id != STATELESS_INPUT_SCHEMA_ID) return error.UnsupportedSchemaId;

    var input: types.StatelessInput = undefined;
    try ssz.deserialize(types.StatelessInput, input_bytes[STATELESS_INPUT_SCHEMA_ID_SIZE..], &input, allocator);

    if (input.chain_config.chain_id != @import("build_options").chain_id) return error.UnexpectedChainid;

    var new_payload_request_root: [32]u8 = undefined;
    try ssz.hashTreeRoot(zevm.crypto.hash.Sha256, types.NewPayloadRequest, input.new_payload_request, &new_payload_request_root, allocator);

    var res: types.StatelessValidationResult = .{
        .chain_config = input.chain_config,
        .new_payload_request_root = new_payload_request_root,
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
    const headers = try allocator.alloc(zevm.types.BlockHeader, input.witness.headers.len());
    const header_hashes = try allocator.alloc([32]u8, input.witness.headers.len());
    for (input.witness.headers.constSlice(), 0..) |*header_bytes, i| {
        header_hashes[i] = zevm.crypto.hash.keccak256(header_bytes.constSlice());
        _ = try rlp.deserialize(zevm.types.BlockHeader, allocator, header_bytes.constSlice(), &headers[i]);
        if (i > 0 and !std.mem.eql(u8, &header_hashes[i - 1], &headers[i].parent_hash)) {
            return error.InvalidAncestors;
        }
    }

    if (headers.len == 0) return error.MissingParentHeader;
    const parent = &headers[headers.len - 1];
    var block = try makeBlock(allocator, &input.new_payload_request, input.public_keys.constSlice());

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
        zevm.chainspec.chainSpecByFork(spec.fork, @import("build_options").chain_id),
        &block,
        parent,
        ancestors,
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
    _ = try committed.code(acc.code_hash);
}

fn makeBlock(
    allocator: std.mem.Allocator,
    request: *const types.NewPayloadRequest,
    public_keys: []const [65]u8,
) !zevm.processor.PreprocessedBlock {
    const payload = &request.execution_payload;

    const txs = try allocator.alloc(zevm.types.Transaction, payload.transactions.len());
    const raw_txs = try allocator.alloc(rlp.RawValue, payload.transactions.len());
    defer allocator.free(raw_txs);
    for (payload.transactions.constSlice(), 0..) |*raw, i| {
        _ = try txs[i].decodeFromRLP(allocator, raw.constSlice());
        raw_txs[i] = .{ .value = raw.constSlice() };
    }

    const senders = try allocator.alloc(u160, payload.transactions.len());
    for (public_keys, 0..) |pk, i| senders[i] = zevm.crypto.curve.addressFromPubkey(pk);

    const withdrawals = try allocator.alloc(zevm.types.Withdrawal, payload.withdrawals.len());
    for (payload.withdrawals.constSlice(), withdrawals) |*src, *dst| {
        dst.* = .{
            .index = src.index,
            .validator_index = src.validator_index,
            .address = src.address,
            .amount = src.amount,
        };
    }

    if (payload.base_fee_per_gas > std.math.maxInt(u64)) return error.BaseFeeTooLarge;

    var bal: zevm.types.BlockAccessLists = undefined;
    _ = try rlp.deserialize(zevm.types.BlockAccessLists, allocator, request.execution_payload.block_access_list.constSlice(), &bal);
    const bal_hash = zevm.crypto.hash.keccak256(request.execution_payload.block_access_list.constSlice());
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
        .extra_data = payload.extra_data.constSlice(),
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

fn sortPairsByKey(comptime V: type, keys: [][32]u8, values: []V) void {
    const Ctx = struct {
        keys: [][32]u8,
        values: []V,
        pub fn lessThan(self: @This(), a: usize, b: usize) bool {
            return std.mem.order(u8, &self.keys[a], &self.keys[b]) == .lt;
        }
        pub fn swap(self: @This(), a: usize, b: usize) void {
            std.mem.swap([32]u8, &self.keys[a], &self.keys[b]);
            std.mem.swap(V, &self.values[a], &self.values[b]);
        }
    };
    std.sort.pdqContext(0, keys.len, Ctx{ .keys = keys, .values = values });
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
            const values = try allocator.alloc(?u256, acc_change_entry.storage_changes.len);
            defer allocator.free(values);
            for (acc_change_entry.storage_changes, keys, values) |slot_change, *k, *v| {
                k.* = committed_state.keccakOfU256(slot_change.key);
                const post_value = try state.contract_state.read(.{ .address = acc_change_entry.addr, .slot = slot_change.key });
                v.* = if (post_value == 0) null else post_value;
            }
            sortPairsByKey(?u256, keys, values);
            try storage_trie.insert(keys, values);
            post_acc.storage_hash = try storage_trie.rootHash();
        }

        state_keys[n_dirty] = committed_state.keccakOfU160(acc_change_entry.addr);
        state_accounts[n_dirty] = if (post_acc.isEmptyAccount()) null else post_acc;
        n_dirty += 1;
    }

    if (n_dirty > 0) {
        sortPairsByKey(?zevm.types.Account, state_keys[0..n_dirty], state_accounts[0..n_dirty]);
        try state_trie.insert(state_keys[0..n_dirty], state_accounts[0..n_dirty]);
    }
    return state_trie.rootHash();
}
