const std = @import("std");

pub const Lookup = struct {
    address: u256,
    slot: u256,
};

const Map = std.HashMapUnmanaged(Lookup, u256, struct {
    pub fn eql(_: @This(), a: Lookup, b: Lookup) bool {
        return std.meta.eql(a, b);
    }

    pub fn hash(_: @This(), lookup: Lookup) u64 {
        const addr_limbs: [4]u64 = @bitCast(lookup.address);
        const slot_limbs: [4]u64 = @bitCast(lookup.slot);

        return (addr_limbs[0] ^ addr_limbs[1] ^ addr_limbs[2] ^ addr_limbs[3]) +
            slot_limbs[0] + slot_limbs[1] + slot_limbs[2] + slot_limbs[3];
    }
}, 80);

pub const Storage = struct {
    const Self = @This();

    dirties: Map = .empty,
    journal: std.ArrayListUnmanaged(struct { Lookup, u256 }) = .empty,

    pub fn init(gpa: std.mem.Allocator, max_dirties: usize, max_journal: usize) !Self {
        var self = Self{};
        try self.dirties.ensureTotalCapacity(gpa, max_dirties);
        try self.journal.ensureTotalCapacity(gpa, max_journal);

        return self;
    }

    pub fn deinit(self: *Self, gpa: std.mem.Allocator) void {
        self.dirties.deinit(gpa);
    }

    pub fn read(self: *Self, lookup: Lookup) u256 {
        return self.dirties.get(lookup) orelse 0;
    }

    pub fn write(self: *Self, lookup: Lookup, value: u256) void {
        const entry = self.dirties.getOrPutAssumeCapacity(lookup);
        var old_value = 0;
        if (entry.found_existing) old_value = entry.value_ptr.*;
        self.journal.appendAssumeCapacity(.{ lookup, old_value });
        entry.value_ptr.* = value;
    }

    pub fn snapshot(self: *Self) usize {
        return self.journal.items.len;
    }
};
