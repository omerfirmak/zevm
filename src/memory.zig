const std = @import("std");
const evm = @import("evm.zig");

pub const Memory = @This();

gpa: std.mem.Allocator,
buf: []u8,

pub fn init(gpa: std.mem.Allocator) !Memory {
    return Memory{
        .gpa = gpa,
        .buf = try gpa.alloc(u8, 0),
    };
}

pub fn slice(self: *Memory, start: u64, size: u64) []u8 {
    const sliceSize = @min(self.buf.len - start, size);
    return self.buf[start .. start + sliceSize];
}

// Tries to grow the memory to fit the given region if there is enough gas
// Returns the amount of gas consumed
pub fn growToFit(self: *Memory, offset: u256, size: u256, availableGas: i32) !i32 {
    if (size == 0) {
        return 0;
    }
    if (offset > std.math.maxInt(u64) or size > std.math.maxInt(u64)) {
        return evm.Errors.GasOverflow;
    }

    const offset64: u64 = @intCast(offset);
    const size64: u64 = @intCast(size);
    const memSize, const overflown = @addWithOverflow(offset64, size64);
    if (overflown == 1) {
        return evm.Errors.GasOverflow;
    }

    const cost = 0; //todo: calculate
    if (cost > availableGas) {
        return evm.Errors.OutOfGas;
    }

    // todo: debug assert that this never relocates.
    if (self.buf.len < memSize) {
        self.buf = self.gpa.remap(self.buf, memSize).?;
    }
    return cost;
}

// Copies from source to the memory region given. Clears tail part of the memory region
// that wasn't filled if any
pub fn copyAndClearRemaining(self: *Memory, offset: u64, size: u64, source: []const u8) void {
    const destination = self.slice(offset, size);
    @memcpy(destination[0..source.len], source);
    @memset(destination[source.len..], 0);
}
