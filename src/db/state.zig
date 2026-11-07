// Copyright (c) 2025-2026 zevm authors
// SPDX-License-Identifier: MIT OR Apache-2.0

const std = @import("std");
const rlp = @import("rlp");
const types = @import("../types.zig");
const kv = @import("kv.zig");

const EthDb = @import("eth.zig").Eth;
const Blockchain = @import("../node/blockchain.zig").Blockchain;

pub const CommittedState = struct {
    const Self = @This();

    eth: *EthDb,
    txn: kv.Transaction,
    storage_cursor: kv.Cursor,

    blockchain: *Blockchain,

    pub fn init(eth: *EthDb, txn: kv.Transaction, blockchain: *Blockchain) !Self {
        return .{
            .eth = eth,
            .txn = txn,
            .storage_cursor = try eth.kv_store.table(txn, .storage).cursor(),
            .blockchain = blockchain,
        };
    }

    pub fn deinit(self: *Self) void {
        self.storage_cursor.deinit();
    }

    pub fn account(self: *const Self, addr: u160) !types.Account {
        return try self.eth.readAccount(self.txn, keccakOfU160(addr)) orelse .{
            .nonce = 0,
            .balance = 0,
            .code_hash = types.empty_code_hash,
            .storage_hash = types.empty_root_hash,
        };
    }

    pub fn storage(self: *const Self, key: types.StorageLookup) !u256 {
        const value_rlp = try self.eth.readStorage(
            self.storage_cursor,
            keccakOfU160(key.address),
            keccakOfU256(key.slot),
        ) orelse return 0;

        var value: u256 = undefined;
        _ = try rlp.deserialize(u256, undefined, value_rlp, &value);
        return value;
    }

    pub fn code(self: *const Self, hash: [32]u8) ![]const u8 {
        return try self.eth.kv_store.table(self.txn, .codes).get(&hash) orelse error.NotFound;
    }

    pub fn blockHash(self: *const Self, number: u64) !u256 {
        const header = try self.blockchain.readHeader(number) orelse return error.MissingAncestorHash;
        return std.mem.readInt(u256, &header.hash(), .big);
    }
};

pub fn keccakOfU160(v: u160) [32]u8 {
    var buf: [20]u8 = undefined;
    std.mem.writeInt(u160, &buf, v, .big);
    var out: [32]u8 = undefined;
    std.crypto.hash.sha3.Keccak256.hash(&buf, &out, .{});
    return out;
}

pub fn keccakOfU256(v: u256) [32]u8 {
    var buf: [32]u8 = undefined;
    std.mem.writeInt(u256, &buf, v, .big);
    var out: [32]u8 = undefined;
    std.crypto.hash.sha3.Keccak256.hash(&buf, &out, .{});
    return out;
}
