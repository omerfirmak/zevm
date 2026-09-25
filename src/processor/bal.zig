const std = @import("std");
const types = @import("../types.zig");
const storage = @import("../evm/storage.zig");
const State = @import("../evm/state.zig").State;

fn atIndex(slice: anytype, index: u32) bool {
    return slice.len > 0 and slice[0].index == index;
}

const AccountEntry = struct {
    changes: types.AccountChanges,
    last_seen_index: u32 = 0,
};

const SlotEntry = struct {
    slot_changes: types.SlotChanges,
    last_seen_index: u32 = 0,
};

pub const Prepared = struct {
    original: *const types.BlockAccessLists,
    map: storage.AddressKeyedMap(AccountEntry),
    slot_map: storage.SlotKeyedMap(SlotEntry),
    valid: bool,

    pub fn init(gpa: std.mem.Allocator, bal: *const types.BlockAccessLists, block_gas_limit: u64, comptime item_cost: u32) !?Prepared {
        var self: Prepared = .{ .map = .empty, .slot_map = .empty, .valid = true, .original = bal };

        var total_keys: u64 = 0;
        for (bal.*) |*account| {
            total_keys += account.storage_changes.len + account.storage_reads.len;
        }
        if (total_keys + bal.len > block_gas_limit / item_cost) return null;

        try self.map.ensureTotalCapacity(gpa, @intCast(bal.len));
        try self.slot_map.ensureTotalCapacity(gpa, @intCast(total_keys));

        var prev_addr: ?u160 = null;
        for (bal.*) |account| {
            if (prev_addr) |prev| if (account.addr <= prev) return null;
            prev_addr = account.addr;
            self.map.putAssumeCapacity(account.addr, .{ .changes = account });

            var prev_key: ?u256 = null;
            for (account.storage_changes) |sc| {
                if (sc.changes.len == 0) return null;
                if (prev_key) |prev| if (sc.key <= prev) return null;
                prev_key = sc.key;
                const lookup: types.StorageLookup = .{ .address = account.addr, .slot = sc.key };
                self.slot_map.putAssumeCapacity(lookup, .{ .slot_changes = sc });
            }

            var prev_read: ?u256 = null;
            for (account.storage_reads) |key| {
                if (prev_read) |prev| if (key <= prev) return null;
                prev_read = key;
                // track reads too, so validateWrites can do dedup on net-zero writes using last_seen_index
                const entry = self.slot_map.getOrPutAssumeCapacity(.{ .address = account.addr, .slot = key });
                if (entry.found_existing) return null;
                entry.value_ptr.* = .{ .slot_changes = .{ .key = key, .changes = &.{} } };
            }
        }
        return self;
    }

    pub fn validateWrites(self: *Prepared, index: u32, state: *State) void {
        if (!self.valid) return;

        var it = state.accounts.dirtiesIterator();
        while (it.next()) |dirty| {
            const map_entry, const old = dirty;
            const new = map_entry.value_ptr;

            var entry = self.map.getEntry(map_entry.key_ptr.*) orelse {
                self.valid = false;
                continue;
            };
            if (entry.value_ptr.last_seen_index > index) continue;
            entry.value_ptr.last_seen_index = index + 1;

            const exp = &entry.value_ptr.changes;

            const expect_nonce = atIndex(exp.nonce_changes, index);
            if (expect_nonce != (old.nonce != new.nonce)) self.valid = false;
            if (expect_nonce) {
                if (exp.nonce_changes[0].nonce != new.nonce) self.valid = false;
                exp.nonce_changes = exp.nonce_changes[1..];
            }

            const expect_balance = atIndex(exp.balance_changes, index);
            if (expect_balance != (old.balance != new.balance)) self.valid = false;
            if (expect_balance) {
                if (exp.balance_changes[0].balance != new.balance) self.valid = false;
                exp.balance_changes = exp.balance_changes[1..];
            }

            const expect_code = atIndex(exp.code_changes, index);
            if (expect_code != !std.meta.eql(old.code_hash, new.code_hash)) self.valid = false;
            if (expect_code) {
                var actual_code: []const u8 = &[_]u8{};
                if (!std.meta.eql(new.code_hash, types.empty_code_hash))
                    actual_code = state.code_storage.get(new.code_hash).?.bytes;
                if (!std.mem.eql(u8, actual_code, exp.code_changes[0].code)) self.valid = false;
                exp.code_changes = exp.code_changes[1..];
            }
        }

        var slot_it = state.contract_state.dirtiesIterator();
        while (slot_it.next()) |dirty| {
            const slot_entry, const old_value = dirty;
            const lookup = slot_entry.key_ptr.*;
            const new_value = slot_entry.value_ptr.*;
            const pre_tx = old_value.*;

            // every written slot must appear in the BAL, either as a change or as a read
            var map_entry = self.slot_map.getEntry(lookup) orelse {
                self.valid = false;
                continue;
            };
            if (map_entry.value_ptr.last_seen_index > index) continue;
            map_entry.value_ptr.last_seen_index = index + 1;

            if (pre_tx == new_value) continue;

            const sc = &map_entry.value_ptr.slot_changes;
            const expect_change = atIndex(sc.changes, index);
            if (!expect_change) self.valid = false;
            if (expect_change) {
                if (sc.changes[0].value != new_value) self.valid = false;
                sc.changes = sc.changes[1..];
            }
        }
    }

    pub fn postExecutionCheck(self: *Prepared, state: *State) bool {
        if (!self.valid) return false;

        // Check to make sure writes were all matched
        var it = self.map.valueIterator();
        while (it.next()) |entry| {
            const exp = entry.changes;
            if (exp.nonce_changes.len != 0) return false;
            if (exp.balance_changes.len != 0) return false;
            if (exp.code_changes.len != 0) return false;
        }

        var slot_it = self.slot_map.valueIterator();
        while (slot_it.next()) |entry| {
            if (entry.slot_changes.changes.len != 0) return false;
        }

        for (self.original.*) |*account| {
            if (!state.accounts.dirties.contains(account.addr)) {
                return false;
            }

            for (account.storage_reads) |s| {
                if (!state.contract_state.dirties.contains(.{ .address = account.addr, .slot = s })) {
                    return false;
                }
            }
        }

        if (self.original.len != state.accounts.dirties.size) return false;
        if (self.slot_map.size != state.contract_state.dirties.size) return false;
        return true;
    }
};
