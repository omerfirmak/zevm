// Copyright (c) 2025-2026 zevm authors
// SPDX-License-Identifier: MIT OR Apache-2.0

const std = @import("std");
const types = @import("../types.zig");
const crypto = @import("../evm/crypto/hash.zig");

const DbState = @import("../db/state.zig").CommittedState;
const Head = @import("engine.zig").Engine.Head;

pub const CommittedState = struct {
    const Self = @This();

    db: DbState,
    head: ?*const Head,

    pub fn init(db: DbState, head: ?*const Head) Self {
        return .{ .db = db, .head = head };
    }

    pub fn deinit(self: *Self) void {
        self.db.deinit();
    }

    pub fn account(self: *const Self, addr: u160) !types.Account {
        var it = self.head;
        while (it) |head| : (it = head.parent) {
            const entry = head.block.state_diff.accounts.getPtr(addr) orelse continue;
            if (entry.changes.readOnly()) continue;
            return error.TODO;
        }
        return self.db.account(addr);
    }

    pub fn storage(self: *const Self, key: types.StorageLookup) !u256 {
        var it = self.head;
        while (it) |head| : (it = head.parent) {
            const entry = head.block.state_diff.slots.getPtr(key) orelse continue;
            if (entry.slot_changes.changes.len > 0) return entry.slot_changes.lastValue();
        }
        return self.db.storage(key);
    }

    pub fn code(self: *const Self, hash: [32]u8) ![]const u8 {
        return self.db.code(hash) catch return error.TODO;
    }

    pub fn blockHash(self: *const Self, number: u64) !u256 {
        var it = self.head;
        while (it) |head| : (it = head.parent) {
            if (head.block.header.number == number) return std.mem.readInt(u256, &head.block.header.hash(), .big);
            if (head.block.header.number < number) break;
        }
        return self.db.blockHash(number);
    }
};
