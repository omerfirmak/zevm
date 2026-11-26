// Copyright (c) 2025-2026 zevm authors
// SPDX-License-Identifier: MIT OR Apache-2.0

const std = @import("std");
const rlp = @import("rlp");
const types = @import("../types.zig");
const kv = @import("kv.zig");
const lmdbx = @import("lmdbx");

const EthDb = @import("eth.zig").Eth;

pub const Errors = lmdbx.Error || rlp.DeserializationError || error{
    NotFound,
    MissingAncestorHash,
    HeaderReadFailed,
    MalformedStorageEntry,
};

pub const CommittedState = struct {
    const Self = @This();

    eth: *EthDb,
    txn: kv.Transaction,
    storage_cursor: kv.Cursor,

    pub fn init(eth: *EthDb, txn: kv.Transaction) !Self {
        return .{
            .eth = eth,
            .txn = txn,
            .storage_cursor = try eth.kv_store.table(txn, .storage).cursor(),
        };
    }

    pub fn deinit(self: *Self) void {
        self.storage_cursor.deinit();
    }

    pub fn account(self: *const Self, addr: u160) Errors!types.Account {
        return try self.eth.readAccount(self.txn, types.keccakOfU160(addr)) orelse .{
            .nonce = 0,
            .balance = 0,
            .code_hash = types.empty_code_hash,
            .storage_hash = types.empty_root_hash,
        };
    }

    pub fn storage(self: *const Self, key: types.StorageLookup) Errors!u256 {
        const value_rlp = try self.eth.readStorage(
            self.storage_cursor,
            types.keccakOfU160(key.address),
            types.keccakOfU256(key.slot),
        ) orelse return 0;

        var value: u256 = undefined;
        _ = try rlp.deserialize(u256, undefined, value_rlp, &value);
        return value;
    }

    pub fn code(self: *const Self, hash: [32]u8) Errors![]const u8 {
        return try self.eth.kv_store.table(self.txn, .codes).get(&hash) orelse Errors.NotFound;
    }

    pub fn blockHash(self: *const Self, number: u64) Errors!u256 {
        const header = (self.eth.readHeader(number) catch return Errors.HeaderReadFailed) orelse return Errors.MissingAncestorHash;
        return std.mem.readInt(u256, &header.hash(), .big);
    }
};
