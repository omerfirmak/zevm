const std = @import("std");
const state = @import("state.zig");
const Bytecode = @import("bytecode.zig").Bytecode;

// Key type for the global contract state storage
pub const StorageLookup = struct {
    address: u256,
    slot: u256,
};

pub fn SlotKeyedMap(comptime T: type) type {
    return std.HashMapUnmanaged(StorageLookup, T, struct {
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
}

pub fn AddressKeyedMap(comptime T: type) type {
    return std.HashMapUnmanaged(u160, T, struct {
        pub fn eql(_: @This(), a: u160, b: u160) bool {
            return a == b;
        }

        pub fn hash(_: @This(), address: u160) u64 {
            const addr_limbs: [3]u64 = @bitCast(@as(u192, @intCast(address)));
            return (addr_limbs[0] ^ addr_limbs[1] ^ addr_limbs[2]);
        }
    }, 80);
}

pub const AccountsAccessList = JournaledStorage(u160, void, AddressKeyedMap(void), {});

pub const AccountStorage = JournaledStorage(u160, state.Account, AddressKeyedMap(state.Account), .{
    .nonce = 0,
    .balance = 0,
    .code_hash = state.empty_code_hash,
    .storage_hash = state.empty_root_hash,
});

pub const ContractStorage = JournaledStorage(StorageLookup, u256, SlotKeyedMap(u256), 0);

pub const SlotsAccessList = JournaledStorage(StorageLookup, void, SlotKeyedMap(void), {});

pub const Lifecycle = enum(u2) { None, Created, Selfdestructed };

pub const CreatedAccounts = JournaledStorage(u160, Lifecycle, AddressKeyedMap(Lifecycle), .None);

// In-memory journaled storage with snapshot/revert support.
// `dirties` holds the current (modified) values. `journal` records every write
// as { key, old_value } so any prefix of writes can be rolled back to a snapshot.
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
            self.journal.deinit(gpa);
        }

        pub fn read(self: *Self, key: Key) Value {
            return self.dirties.get(key) orelse empty_value;
        }

        // Writes a value and journals the old value for revert. Returns { old_value, was_present }.
        pub fn write(self: *Self, key: Key, value: Value) struct { Value, bool } {
            const entry = self.dirties.getOrPutAssumeCapacity(key);
            var old_value = empty_value;
            if (entry.found_existing) old_value = entry.value_ptr.*;
            self.journal.appendAssumeCapacity(.{ .key = key, .old_value = old_value });
            entry.value_ptr.* = value;
            return .{ old_value, entry.found_existing };
        }

        // Writes only if the key is not already present. Returns true if the key was new.
        // Used for access list tracking (EIP-2929): first access marks warm, subsequent calls no-op.
        pub fn writeNoClobber(self: *Self, key: Key, value: Value) bool {
            const entry = self.dirties.getOrPutAssumeCapacity(key);
            if (entry.found_existing) return false;
            self.journal.appendAssumeCapacity(.{ .key = key, .old_value = empty_value });
            entry.value_ptr.* = value;
            return true;
        }

        // Returns a mutable pointer for in-place modification, journaling the pre-update value.
        pub fn update(self: *Self, key: Key) *Value {
            const entry = self.dirties.getOrPutAssumeCapacity(key);
            if (!entry.found_existing) entry.value_ptr.* = empty_value;
            self.journal.appendAssumeCapacity(.{ .key = key, .old_value = entry.value_ptr.* });
            return entry.value_ptr;
        }

        // Returns an opaque ID representing the current journal position.
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

// Backing storage for the contract code
pub const CodeStorage = std.HashMapUnmanaged(u256, Bytecode, struct {
    pub fn eql(_: @This(), a: u256, b: u256) bool {
        return a == b;
    }

    pub fn hash(_: @This(), codehash: u256) u64 {
        const hash_limbs: [4]u64 = @bitCast(codehash);
        return (hash_limbs[0] ^ hash_limbs[1] ^ hash_limbs[2] ^ hash_limbs[3]);
    }
}, 80);
