// Copyright (c) 2025-2026 zevm authors
// SPDX-License-Identifier: MIT OR Apache-2.0

const std = @import("std");
const types = @import("../types.zig");
const processor = @import("../processor/processor.zig");
const kv = @import("../db/kv.zig");
const trie = @import("../trie/trie.zig");
const Blockchain = @import("blockchain.zig").Blockchain;

pub const ValidatedBlock = struct {
    hashed_bal: types.HashedBlockAccessLists,
    storage_collectors: []?trie.NodeCollector,
    account_collector: trie.NodeCollector,
};

pub const Validator = struct {
    const Self = @This();

    gpa: std.mem.Allocator,
    chain: *const Blockchain,

    pub fn init(gpa: std.mem.Allocator, chain: *const Blockchain) Self {
        return .{ .gpa = gpa, .chain = chain };
    }

    // pub fn validate(
    //     self: *const Self,
    //     arena: std.mem.Allocator,
    //     block: processor.PreprocessedBlock,
    // ) !ValidatedBlock {}

    pub fn validateStateRoot(
        self: *const Self,
        allocator: std.mem.Allocator,
        txn: kv.Transaction,
        parent_root: [32]u8,
        state_root: [32]u8,
        bal: types.BlockAccessLists,
    ) !ValidatedBlock {
        var scratch_arena = std.heap.ArenaAllocator.init(self.gpa);
        defer scratch_arena.deinit();
        const scratch = scratch_arena.allocator();
        const eth_db = self.chain.eth_db;
        const hashed_bal = try types.HashedBlockAccessLists.init(allocator, bal);
        const accounts_cursor = try eth_db.kv_store.table(txn, .accounts).cursor();
        defer accounts_cursor.deinit();
        var storage_resolver = try eth_db.openStorageTrieResolver(txn);
        defer storage_resolver.deinit();

        const storage_collectors = try allocator.alloc(?trie.NodeCollector, bal.len);
        @memset(storage_collectors, null);
        const account_keys = try scratch.alloc([32]u8, bal.len);
        const accounts = try scratch.alloc(?types.Account, bal.len);
        var updated: usize = 0;

        for (hashed_bal.changes, hashed_bal.account_hashes, hashed_bal.slot_hashes, storage_collectors) |
            changes,
            account_hash,
            slot_hashes,
            *collector,
        | {
            if (changes.readOnly()) continue;
            const account_diff = try changes.accountDiff();

            var account = types.EmptyAccount;
            if (try eth_db.seekAccount(accounts_cursor, account_hash)) |entry| {
                if (std.mem.eql(u8, &entry.hash, &account_hash)) account = entry.account;
            }

            if (account_diff.balance) |balance| account.balance = balance;
            if (account_diff.nonce) |nonce| account.nonce = nonce;
            if (account_diff.code) |code| std.crypto.hash.sha3.Keccak256.hash(code, &account.code_hash, .{});

            if (slot_hashes.len > 0) {
                const values = try scratch.alloc(u256, slot_hashes.len);
                for (changes.storage_changes, values) |slot, *value| value.* = slot.lastValue();

                collector.* = try trie.NodeCollector.init(allocator, slot_hashes.len * 66);
                var storage_trie = eth_db.openStorageTrieWithResolver(
                    scratch,
                    &storage_resolver,
                    account_hash,
                    account.storage_hash,
                ).withCollector(&collector.*.?);
                try storage_trie.update(slot_hashes, values);
                account.storage_hash = try storage_trie.rootHash();
            }

            account_keys[updated] = account_hash;
            accounts[updated] = if (account.isEmpty()) null else account;
            updated += 1;
        }

        var account_collector = try trie.NodeCollector.init(allocator, updated * 66);
        if (updated > 0) {
            const at = try eth_db.openAccountTrie(scratch, txn, parent_root);
            defer eth_db.closeAccountTrie(&at);
            var account_trie = at.withCollector(&account_collector);
            try account_trie.update(account_keys[0..updated], accounts[0..updated]);
            if (!std.meta.eql(try account_trie.rootHash(), state_root)) return error.StateRootMismatch;
        } else if (!std.meta.eql(parent_root, state_root)) return error.StateRootMismatch;

        return .{
            .hashed_bal = hashed_bal,
            .storage_collectors = storage_collectors,
            .account_collector = account_collector,
        };
    }
};
