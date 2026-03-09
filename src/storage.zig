const std = @import("std");
const state = @import("state.zig");

// Key type for the global contract state storage
pub const StorageLookup = struct {
    address: u256,
    slot: u256,
};

// Backing storage for the contract state. Uses a light hashing algorithm for OA
const StorageMap = std.HashMapUnmanaged(StorageLookup, u256, struct {
    pub fn eql(_: @This(), a: StorageLookup, b: StorageLookup) bool {
        return std.meta.eql(a, b);
    }

    pub fn hash(_: @This(), lookup: StorageLookup) u64 {
        const addr_limbs: [4]u64 = @bitCast(lookup.address);
        const slot_limbs: [4]u64 = @bitCast(lookup.slot);

        return (addr_limbs[0] ^ addr_limbs[1] ^ addr_limbs[2] ^ addr_limbs[3]) +%
            slot_limbs[0] +% slot_limbs[1] +% slot_limbs[2] +% slot_limbs[3];
    }
}, 80);

pub const AccountStorage = JournaledStorage(u160, state.Account, AccountMap, .{
    .nonce = 0,
    .balance = 0,
    .code_hash = state.empty_code_hash,
    .storage_hash = state.empty_root_hash,
});

// Backing storage for the account state
const AccountMap = std.HashMapUnmanaged(u160, state.Account, struct {
    pub fn eql(_: @This(), a: u160, b: u160) bool {
        return a == b;
    }

    pub fn hash(_: @This(), address: u160) u64 {
        const addr_limbs: [3]u64 = @bitCast(@as(u192, @intCast(address)));
        return (addr_limbs[0] ^ addr_limbs[1] ^ addr_limbs[2]);
    }
}, 80);

pub const ContractStorage = JournaledStorage(StorageLookup, u256, StorageMap, 0);

// In-memory journaled storage
pub fn JournaledStorage(comptime Key: type, comptime Value: type, comptime Map: type, comptime empty_value: Value) type {
    return struct {
        const Self = @This();

        dirties: Map = .empty,
        journal: std.ArrayListUnmanaged(struct { key: Key, old_value: Value }) = .empty,

        pub fn init(gpa: std.mem.Allocator, max_dirties: u32, max_journal: u32) !Self {
            var self = Self{};
            try self.dirties.ensureTotalCapacity(gpa, max_dirties);
            try self.journal.ensureTotalCapacity(gpa, max_journal);

            return self;
        }

        pub fn deinit(self: *Self, gpa: std.mem.Allocator) void {
            self.dirties.deinit(gpa);
        }

        pub fn read(self: *Self, key: Key) Value {
            return self.dirties.get(key) orelse empty_value;
        }

        pub fn write(self: *Self, key: Key, value: Value) Value {
            const entry = self.dirties.getOrPutAssumeCapacity(key);
            var old_value = empty_value;
            if (entry.found_existing) old_value = entry.value_ptr.*;
            self.journal.appendAssumeCapacity(.{ .key = key, .old_value = old_value });
            entry.value_ptr.* = value;
            return old_value;
        }

        pub fn snapshot(self: *Self) usize {
            return self.journal.items.len;
        }

        pub fn revert(self: *Self, snapshot_id: usize) void {
            std.debug.assert(self.journal.items.len >= snapshot_id);
            for (0..self.journal.items.len - snapshot_id) |_| {
                const entry = self.journal.pop().?;
                if (std.meta.eql(entry.old_value, empty_value)) {
                    _ = self.dirties.remove(entry.key);
                } else {
                    self.dirties.putAssumeCapacity(entry.key, entry.old_value);
                }
            }
        }
    };
}

test "semcheck" {
    std.testing.refAllDecls(AccountStorage);
    std.testing.refAllDecls(ContractStorage);
}
