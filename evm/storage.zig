const std = @import("std");
const types = @import("types");
const Bytecode = @import("bytecode.zig").Bytecode;
const CommittedState = @import("committed_state").CommittedState;

pub fn SlotKeyedMap(comptime T: type) type {
    return std.HashMapUnmanaged(types.StorageLookup, T, struct {
        pub fn eql(_: @This(), a: types.StorageLookup, b: types.StorageLookup) bool {
            return std.meta.eql(a, b);
        }

        pub fn hash(_: @This(), lookup: types.StorageLookup) u64 {
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

pub const CommittedAccount = struct {
    inner: *const CommittedState,
    pub fn read(self: @This(), key: u160) types.Account {
        return self.inner.account(key);
    }
};

pub const CommittedStorage = struct {
    inner: *const CommittedState,
    pub fn read(self: @This(), key: types.StorageLookup) u256 {
        return self.inner.storage(key);
    }
};

pub const AccountsAccessList = JournaledStorage(u160, void, AddressKeyedMap(void), void);

pub const AccountStorage = JournaledStorage(u160, types.Account, AddressKeyedMap(types.Account), CommittedAccount);

pub const ContractStorage = JournaledStorage(types.StorageLookup, u256, SlotKeyedMap(u256), CommittedStorage);

pub const TransientStorage = JournaledStorage(types.StorageLookup, u256, SlotKeyedMap(u256), void);

pub const SlotsAccessList = JournaledStorage(types.StorageLookup, void, SlotKeyedMap(void), void);

pub const Lifecycle = enum(u2) { None = 0, Created, Selfdestructed };

pub const CreatedAccounts = JournaledStorage(u160, Lifecycle, AddressKeyedMap(Lifecycle), void);

// In-memory journaled storage with snapshot/revert support.
// `dirties` holds the current (modified) values. `journal` records every write
// as { key, old_value } so any prefix of writes can be rolled back to a snapshot.
pub fn JournaledStorage(comptime Key: type, comptime Value: type, comptime Map: type, comptime Committed: type) type {
    return struct {
        const Self = @This();

        const zero_value = std.mem.zeroes(Value);
        committed: Committed,

        dirties: Map = .empty,
        journal: std.ArrayListUnmanaged(struct { key: Key, old_value: Value }) = .empty,

        pub fn init(gpa: std.mem.Allocator, max_dirties: u32, max_journal: u32, committed: Committed) !Self {
            var self = Self{
                .committed = committed,
            };
            try self.dirties.ensureTotalCapacity(gpa, max_dirties);
            try self.journal.ensureTotalCapacity(gpa, max_journal);

            return self;
        }

        pub fn deinit(self: *Self, gpa: std.mem.Allocator) void {
            self.dirties.deinit(gpa);
            self.journal.deinit(gpa);
        }

        pub fn committedOrZero(self: *Self, key: Key) Value {
            return if (Committed == void)
                zero_value
            else
                self.committed.read(key);
        }

        pub fn read(self: *Self, key: Key) Value {
            return self.dirties.get(key) orelse self.committedOrZero(key);
        }

        // Writes a value and journals the old value for revert. Returns { old_value, was_present }.
        pub fn write(self: *Self, key: Key, value: Value) struct { Value, bool } {
            const entry = self.dirties.getOrPutAssumeCapacity(key);
            const old_value = if (entry.found_existing) entry.value_ptr.* else self.committedOrZero(key);
            self.journal.appendAssumeCapacity(.{ .key = key, .old_value = old_value });
            entry.value_ptr.* = value;
            return .{ old_value, entry.found_existing };
        }

        // Writes only if the key is not already present. Returns true if the key was new.
        // Used for access list tracking (EIP-2929): first access marks warm, subsequent calls no-op.
        pub fn writeNoClobber(self: *Self, key: Key, value: Value) bool {
            if (Committed != void) @compileError("writeNoClobber not supported with committed state");
            const entry = self.dirties.getOrPutAssumeCapacity(key);
            if (entry.found_existing) return false;
            self.journal.appendAssumeCapacity(.{ .key = key, .old_value = self.committedOrZero(key) });
            entry.value_ptr.* = value;
            return true;
        }

        // Returns a mutable pointer for in-place modification, journaling the pre-update value.
        pub fn update(self: *Self, key: Key) *Value {
            const entry = self.dirties.getOrPutAssumeCapacity(key);
            if (!entry.found_existing) entry.value_ptr.* = self.committedOrZero(key);
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
                if (Committed == void and std.meta.eql(entry.old_value, zero_value)) {
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
