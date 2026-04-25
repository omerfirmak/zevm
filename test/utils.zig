const std = @import("std");
const zevm = @import("zevm");
const evm = zevm.evm;
const state_mod = zevm.state;
const types = zevm.types;
const CommittedState = @import("committed_state").CommittedState;

pub fn parseHex(comptime T: type, str: []const u8) !T {
    const hex = if (std.mem.startsWith(u8, str, "0x")) str[2..] else str;
    if (hex.len == 0) return 0;
    return std.fmt.parseInt(T, hex, 16);
}

pub fn HexInt(comptime Int: type) type {
    return struct {
        value: Int,

        pub fn jsonParse(allocator: std.mem.Allocator, source: anytype, options: std.json.ParseOptions) !@This() {
            const str = try std.json.innerParse([]const u8, allocator, source, options);
            const hex = if (std.mem.startsWith(u8, str, "0x")) str[2..] else str;
            const value = if (hex.len == 0) 0 else try std.fmt.parseInt(Int, hex, 16);
            return .{ .value = value };
        }
    };
}

// Parses an address field where empty string means "no address" (CREATE tx).
pub const HexAddress = struct {
    value: ?u160,

    pub fn jsonParse(allocator: std.mem.Allocator, source: anytype, options: std.json.ParseOptions) !@This() {
        const str = try std.json.innerParse([]const u8, allocator, source, options);
        const hex = if (std.mem.startsWith(u8, str, "0x")) str[2..] else str;
        if (hex.len == 0) return .{ .value = null };
        return .{ .value = try std.fmt.parseInt(u160, hex, 16) };
    }
};

pub const HexBytes = struct {
    value: []u8,

    pub fn jsonParse(allocator: std.mem.Allocator, source: anytype, options: std.json.ParseOptions) !@This() {
        const str = try std.json.innerParse([]const u8, allocator, source, options);
        const hex = if (std.mem.startsWith(u8, str, "0x")) str[2..] else str;
        if (hex.len == 0) return .{ .value = &.{} };
        const padded_len = hex.len + (hex.len & 1);
        const bytes = try allocator.alloc(u8, padded_len / 2);
        if (hex.len & 1 == 1) {
            // Odd-length hex: left-pad with '0' by parsing manually
            bytes[0] = std.fmt.charToDigit(hex[0], 16) catch return error.InvalidCharacter;
            _ = std.fmt.hexToBytes(bytes[1..], hex[1..]) catch return error.InvalidCharacter;
        } else {
            _ = std.fmt.hexToBytes(bytes, hex) catch return error.InvalidCharacter;
        }
        return .{ .value = bytes };
    }
};

pub const AccountState = struct {
    nonce: HexInt(u64),
    balance: HexInt(u256),
    code: HexBytes,
    storage: std.json.ArrayHashMap(HexInt(u256)),
};

pub const BlobScheduleEntry = struct {
    target: HexInt(u64),
    max: HexInt(u64),
    baseFeeUpdateFraction: HexInt(u64),
};

pub const Config = struct {
    blobSchedule: ?std.json.ArrayHashMap(BlobScheduleEntry) = null,
    chainid: HexInt(u64) = .{ .value = 1 },
};

pub const Info = struct {
    hash: HexBytes,
    comment: []const u8,
    @"filling-transition-tool": []const u8,
    description: []const u8,
    url: []const u8,
    @"fixture-format": []const u8,
    @"reference-spec": ?[]const u8 = null,
    @"reference-spec-version": ?[]const u8 = null,
};

pub fn buildCommittedState(alloc: std.mem.Allocator, pre: std.json.ArrayHashMap(AccountState)) !CommittedState {
    var committed = CommittedState.init(alloc);

    for (pre.map.keys(), pre.map.values()) |addr_str, pre_acct| {
        const addr = try parseHex(u160, addr_str);
        const has_storage = pre_acct.storage.map.count() > 0;

        for (pre_acct.storage.map.keys(), pre_acct.storage.map.values()) |slot_str, slot_val| {
            const slot = try parseHex(u256, slot_str);
            if (slot_val.value != 0) {
                try committed.storage_map.put(.{ .address = addr, .slot = slot }, slot_val.value);
            }
        }

        var code_hash = types.empty_code_hash;
        if (pre_acct.code.value.len > 0) {
            std.crypto.hash.sha3.Keccak256.hash(pre_acct.code.value, &code_hash, .{});
            try committed.code_map.put(code_hash, pre_acct.code.value);
        }

        try committed.account_map.put(addr, .{
            .nonce = pre_acct.nonce.value,
            .balance = pre_acct.balance.value,
            .code_hash = code_hash,
            .storage_hash = if (has_storage) [_]u8{1} ** 32 else types.empty_root_hash,
        });
    }

    return committed;
}

const Keccak256 = std.crypto.hash.sha3.Keccak256;

pub fn keccak256OfU160(v: u160) [32]u8 {
    var buf: [20]u8 = undefined;
    std.mem.writeInt(u160, &buf, v, .big);
    var out: [32]u8 = undefined;
    Keccak256.hash(&buf, &out, .{});
    return out;
}

pub fn keccak256OfU256(v: u256) [32]u8 {
    var buf: [32]u8 = undefined;
    std.mem.writeInt(u256, &buf, v, .big);
    var out: [32]u8 = undefined;
    Keccak256.hash(&buf, &out, .{});
    return out;
}

/// Build the Ethereum world-state trie from `state` and return its 32-byte root hash.
/// Uses `gpa` for intermediate collections and `fba` for trie-node allocations.
pub fn computeStateRoot(
    gpa: std.mem.Allocator,
    fba: *std.heap.FixedBufferAllocator,
    state: *state_mod.State,
    committed: *const CommittedState,
    vm: *evm.EVM,
) ![32]u8 {
    // Collect every address live in committed or dirty state.
    var addresses = std.AutoHashMap(u160, void).init(gpa);
    defer addresses.deinit();
    var pre_it = committed.account_map.keyIterator();
    while (pre_it.next()) |addr| {
        if (try vm.created_accounts.read(addr.*) != .Selfdestructed) {
            try addresses.put(addr.*, {});
        }
    }
    var dirty_acct_it = state.accounts.dirties.keyIterator();
    while (dirty_acct_it.next()) |addr| {
        if (try vm.created_accounts.read(addr.*) != .Selfdestructed) {
            try addresses.put(addr.*, {});
        }
    }

    // Build a sorted list of live accounts: [(keccak256(addr), addr, account)].
    const AddrEntry = struct { key: [32]u8, addr: u160, account: types.Account };
    var acct_list: std.ArrayListUnmanaged(AddrEntry) = .empty;
    defer acct_list.deinit(gpa);

    var addr_it = addresses.keyIterator();
    while (addr_it.next()) |addr_ptr| {
        const addr = addr_ptr.*;
        const account = try state.accounts.read(addr);
        if (account.isEmptyAccount()) continue;
        try acct_list.append(gpa, .{ .key = keccak256OfU160(addr), .addr = addr, .account = account });
    }
    std.sort.pdq(AddrEntry, acct_list.items, {}, struct {
        fn lt(_: void, a: AddrEntry, b: AddrEntry) bool {
            return std.mem.lessThan(u8, &a.key, &b.key);
        }
    }.lt);

    // First pass: compute storage root for each account and store it back.
    for (acct_list.items) |*ae| {
        // Collect storage slots for this account (committed + dirty).
        var slots = std.AutoHashMap(u256, void).init(gpa);
        defer slots.deinit();
        var cs_it = committed.storage_map.keyIterator();
        while (cs_it.next()) |lookup| {
            if (lookup.address == @as(u256, ae.addr)) try slots.put(lookup.slot, {});
        }
        var ds_it = state.contract_state.dirties.keyIterator();
        while (ds_it.next()) |lookup| {
            if (lookup.address == @as(u256, ae.addr)) try slots.put(lookup.slot, {});
        }

        // Build a sorted list of non-zero slots: [(keccak256(slot), slot, value)].
        const SlotEntry = struct { key: [32]u8, slot: u256, value: u256 };
        var slot_list: std.ArrayListUnmanaged(SlotEntry) = .empty;
        defer slot_list.deinit(gpa);
        var slot_it = slots.keyIterator();
        while (slot_it.next()) |slot_ptr| {
            const val = try state.contract_state.read(.{ .address = @as(u256, ae.addr), .slot = slot_ptr.* });
            if (val != 0) try slot_list.append(gpa, .{ .key = keccak256OfU256(slot_ptr.*), .slot = slot_ptr.*, .value = val });
        }
        std.sort.pdq(SlotEntry, slot_list.items, {}, struct {
            fn lt(_: void, a: SlotEntry, b: SlotEntry) bool {
                return std.mem.lessThan(u8, &a.key, &b.key);
            }
        }.lt);

        // Insert into storage trie and reclaim FBA memory after.
        const saved = fba.end_index;
        var storage_trie = try zevm.StorageTrie.init(fba);
        if (slot_list.items.len > 0) {
            const storage_keys = try fba.allocator().alloc([32]u8, slot_list.items.len);
            const storage_vals = try fba.allocator().alloc(u256, slot_list.items.len);
            for (slot_list.items, storage_keys, storage_vals) |se, *k, *v| {
                k.* = se.key;
                v.* = se.value;
            }
            try storage_trie.insert(storage_keys, storage_vals);
        }
        ae.account.storage_hash = try storage_trie.rootHash();
        fba.end_index = saved;
    }

    // Second pass: batch-insert all accounts into the account trie.
    const acct_keys = try gpa.alloc([32]u8, acct_list.items.len);
    defer gpa.free(acct_keys);
    const accounts = try gpa.alloc(types.Account, acct_list.items.len);
    defer gpa.free(accounts);
    for (acct_list.items, acct_keys, accounts) |ae, *k, *a| {
        k.* = ae.key;
        a.* = ae.account;
    }
    var account_trie = try zevm.AccountTrie.init(fba);
    try account_trie.insert(acct_keys, accounts);

    return account_trie.rootHash();
}

pub fn mapException(name: []const u8) ?anyerror {
    const map = .{
        .{ "TransactionException.INSUFFICIENT_ACCOUNT_FUNDS", evm.Errors.NotEnoughFunds },
        .{ "TransactionException.GASLIMIT_PRICE_PRODUCT_OVERFLOW", evm.Errors.GasOverflow },
        .{ "TransactionException.GAS_ALLOWANCE_EXCEEDED", evm.Errors.GasOverflow },
        .{ "TransactionException.GAS_LIMIT_EXCEEDS_MAXIMUM", evm.Errors.GasOverflow },
        .{ "TransactionException.INTRINSIC_GAS_TOO_LOW", evm.Errors.OutOfGas },
        .{ "TransactionException.INTRINSIC_GAS_BELOW_FLOOR_GAS_COST", evm.Errors.OutOfGas },
        .{ "TransactionException.NONCE_IS_MAX", evm.Errors.NonceMax },
        .{ "TransactionException.INITCODE_SIZE_EXCEEDED", evm.Errors.InitcodeSizeExceeded },
        .{ "TransactionException.SENDER_NOT_EOA", evm.Errors.SenderNotEOA },
        .{ "TransactionException.INSUFFICIENT_MAX_FEE_PER_GAS", evm.Errors.FeeTooLow },
        .{ "TransactionException.PRIORITY_GREATER_THAN_MAX_FEE_PER_GAS", evm.Errors.PriorityFeeTooHigh },
        .{ "TransactionException.TYPE_3_TX_ZERO_BLOBS", evm.Errors.ZeroBlobs },
        .{ "TransactionException.TYPE_3_TX_INVALID_BLOB_VERSIONED_HASH", evm.Errors.InvalidBlobVersionedHash },
        .{ "TransactionException.TYPE_3_TX_MAX_BLOB_GAS_ALLOWANCE_EXCEEDED", evm.Errors.TooManyBlobs },
        .{ "TransactionException.TYPE_3_TX_BLOB_COUNT_EXCEEDED", evm.Errors.TooManyBlobs },
        .{ "TransactionException.TYPE_3_TX_CONTRACT_CREATION", evm.Errors.CreateBlobTx },
        .{ "TransactionException.INSUFFICIENT_MAX_FEE_PER_BLOB_GAS", evm.Errors.InsufficientMaxFeePerBlobGas },
        .{ "TransactionException.TYPE_4_EMPTY_AUTHORIZATION_LIST", evm.Errors.EmptyAuthorizationList },
        .{ "TransactionException.TYPE_4_TX_CONTRACT_CREATION", evm.Errors.CreateSetCodeTx },
    };
    inline for (map) |entry| {
        if (std.mem.eql(u8, name, entry[0])) return entry[1];
    }
    return null;
}

// Returns true if `err` satisfies any exception in the `|`-separated list.
pub fn exceptionMatches(err: anyerror, expected: []const u8) bool {
    var it = std.mem.splitScalar(u8, expected, '|');
    while (it.next()) |ex| {
        if (mapException(ex)) |mapped| {
            if (err == mapped) return true;
        }
    }
    return false;
}
