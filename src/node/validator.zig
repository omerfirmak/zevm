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
        io: std.Io,
        arena: std.mem.Allocator,
        parent_root: [32]u8,
        expected_root: [32]u8,
        bal: types.BlockAccessLists,
    ) !ValidatedBlock {
        const txn = try self.chain.eth_db.kv_store.transaction_ro();
        defer txn.abort() catch unreachable;

        var scratch_arena = std.heap.ArenaAllocator.init(self.gpa);
        defer scratch_arena.deinit();
        const scratch = scratch_arena.allocator();

        var total_work: usize = 0;
        var filtered_bal = try arena.alloc(types.AccountChanges, bal.len);
        filtered_bal.len = 0;
        for (bal) |changes| {
            if (changes.readOnly()) continue;
            filtered_bal.len += 1;
            filtered_bal[filtered_bal.len - 1] = changes;
            total_work += 1 + changes.storage_changes.len;
        }

        const hashed_bal = try types.HashedBlockAccessLists.init(arena, filtered_bal);

        const storage_collectors = try arena.alloc(?trie.NodeCollector, filtered_bal.len);
        @memset(storage_collectors, null);
        const account_keys = try scratch.alloc([32]u8, filtered_bal.len);
        const accounts = try scratch.alloc(?types.Account, filtered_bal.len);

        const workers = std.Thread.getCpuCount() catch 1;
        const work_per_worker = @max(1, @divCeil(total_work, workers));

        var work_group = std.Io.Group.init;
        var start: usize = 0;
        var current_work: usize = 0;

        for (hashed_bal.changes, 0..) |*changes, index| {
            current_work += 1 + changes.storage_changes.len;

            if (current_work >= work_per_worker or index == hashed_bal.changes.len - 1) {
                const bal_shard = hashed_bal.slice(start, index + 1);
                work_group.async(io, Validator.updateAccountsShardTask, .{
                    self,                                   txn,
                    bal_shard,                              arena,
                    account_keys[start .. index + 1],       accounts[start .. index + 1],
                    storage_collectors[start .. index + 1],
                });
                start = index + 1;
                current_work = 0;
            }
        }

        try work_group.await(io);

        var account_collector = try trie.NodeCollector.init(arena, filtered_bal.len * 66);
        if (filtered_bal.len > 0) {
            const at = try self.chain.eth_db.openAccountTrie(scratch, txn, parent_root);
            defer self.chain.eth_db.closeAccountTrie(&at);
            var account_trie = at.withCollector(&account_collector);
            try account_trie.update(account_keys, accounts);
            if (!std.meta.eql(try account_trie.rootHash(), expected_root)) return error.StateRootMismatch;
        } else if (!std.meta.eql(parent_root, expected_root)) return error.StateRootMismatch;

        return .{
            .hashed_bal = hashed_bal,
            .storage_collectors = storage_collectors,
            .account_collector = account_collector,
        };
    }

    fn updateAccountsShardTask(
        self: *const Self,
        parent_txn: kv.Transaction,
        bal_shard: types.HashedBlockAccessLists,
        arena: std.mem.Allocator,

        // outputs
        account_keys: [][32]u8,
        accounts: []?types.Account,
        storage_collectors: []?trie.NodeCollector,
    ) !void {
        self.updateAccountsShard(
            parent_txn,
            bal_shard,
            arena,
            account_keys,
            accounts,
            storage_collectors,
        ) catch return std.Io.Cancelable.Canceled;
    }

    fn updateAccountsShard(
        self: *const Self,
        parent_txn: kv.Transaction,
        bal_shard: types.HashedBlockAccessLists,
        arena: std.mem.Allocator,

        // outputs
        account_keys: [][32]u8,
        accounts: []?types.Account,
        storage_collectors: []?trie.NodeCollector,
    ) !void {
        var scratch_arena = std.heap.ArenaAllocator.init(self.gpa);
        defer scratch_arena.deinit();
        const scratch = scratch_arena.allocator();

        const txn = try parent_txn.clone(null);
        defer txn.abort() catch unreachable;

        const accounts_cursor = try self.chain.eth_db.kv_store.table(txn, .accounts).cursor();
        defer accounts_cursor.deinit();
        var storage_resolver = try self.chain.eth_db.openStorageTrieResolver(txn);
        defer storage_resolver.deinit();

        for (bal_shard.changes, bal_shard.account_hashes, bal_shard.slot_hashes, account_keys, accounts, storage_collectors) |
            changes,
            account_hash,
            slot_hashes,
            *account_key,
            *updated_account,
            *collector,
        | {
            const account_diff = try changes.accountDiff();

            var account = types.EmptyAccount;
            if (try self.chain.eth_db.seekAccount(accounts_cursor, account_hash)) |entry| {
                if (std.mem.eql(u8, &entry.hash, &account_hash)) account = entry.account;
            }

            if (account_diff.balance) |balance| account.balance = balance;
            if (account_diff.nonce) |nonce| account.nonce = nonce;
            if (account_diff.code) |code| std.crypto.hash.sha3.Keccak256.hash(code, &account.code_hash, .{});

            if (slot_hashes.len > 0) {
                const values = try scratch.alloc(u256, slot_hashes.len);
                for (changes.storage_changes, values) |slot, *value| value.* = slot.lastValue();

                collector.* = try trie.NodeCollector.init(arena, slot_hashes.len * 66);
                var storage_trie = self.chain.eth_db.openStorageTrieWithResolver(
                    scratch,
                    &storage_resolver,
                    account_hash,
                    account.storage_hash,
                ).withCollector(&collector.*.?);
                try storage_trie.update(slot_hashes, values);
                account.storage_hash = try storage_trie.rootHash();
            }

            account_key.* = account_hash;
            updated_account.* = if (account.isEmpty()) null else account;
        }
    }
};
