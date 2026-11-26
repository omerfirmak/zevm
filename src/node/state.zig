// Copyright (c) 2025-2026 zevm authors
// SPDX-License-Identifier: MIT OR Apache-2.0

const std = @import("std");
const types = @import("../types.zig");
const crypto = @import("../evm/crypto/hash.zig");

const DbState = @import("../db/state.zig").CommittedState;
const Forkchoice = @import("engine.zig").Forkchoice;

pub const Errors = @import("../db/state.zig").Errors || error{StaleState};

pub const CommittedState = struct {
    const Self = @This();

    db: DbState,
    head: ?*const Forkchoice.Head,
    view: Forkchoice.View,

    pub fn init(db: DbState, head: ?*const Forkchoice.Head, view: Forkchoice.View) Self {
        return .{ .db = db, .head = head, .view = view };
    }

    pub fn deinit(self: *Self) void {
        self.db.deinit();
        self.db.txn.abort() catch {};
    }

    pub fn account(self: *const Self, addr: u160) Errors!types.Account {
        try self.view.enter();
        defer self.view.exit();
        var it = self.head;
        while (it) |head| : (it = head.parent) {
            if (head.block.header.number <= self.view.persisted) break;
            const entry = head.block.state_diff.accounts.getPtr(addr) orelse continue;
            if (entry.changes.readOnly()) continue;
            const diff = try entry.changes.accountDiff();

            var acc = entry.pre_block;
            if (diff.nonce) |nonce| acc.nonce = nonce;
            if (diff.balance) |balance| acc.balance = balance;
            if (diff.code) |c| acc.code_hash = crypto.keccak256(c); // todo: avoid
            // todo: storage root
            return acc;
        }
        return self.db.account(addr);
    }

    pub fn storage(self: *const Self, key: types.StorageLookup) Errors!u256 {
        try self.view.enter();
        defer self.view.exit();
        var it = self.head;
        while (it) |head| : (it = head.parent) {
            if (head.block.header.number <= self.view.persisted) break;
            const entry = head.block.state_diff.slots.getPtr(key) orelse continue;
            if (entry.slot_changes.changes.len > 0) return entry.slot_changes.lastValue();
        }
        return self.db.storage(key);
    }

    pub fn code(self: *const Self, hash: [32]u8) Errors![]const u8 {
        try self.view.enter();
        defer self.view.exit();
        var it = self.head;
        while (it) |head| : (it = head.parent) {
            if (head.block.header.number <= self.view.persisted) break;
            var accounts = head.block.state_diff.accounts.valueIterator();
            while (accounts.next()) |entry| {
                for (entry.changes.code_changes) |c| {
                    if (std.mem.eql(u8, &crypto.keccak256(c.code), &hash)) return c.code; // todo avoid
                }
            }
        }
        return self.db.code(hash);
    }

    pub fn blockHash(self: *const Self, number: u64) Errors!u256 {
        try self.view.enter();
        defer self.view.exit();
        var it = self.head;
        while (it) |head| : (it = head.parent) {
            if (head.block.header.number <= self.view.persisted) break;
            if (head.block.header.number == number) return std.mem.readInt(u256, &head.block.header.hash(), .big);
            if (head.block.header.number < number) break;
        }
        return self.db.blockHash(number);
    }
};
