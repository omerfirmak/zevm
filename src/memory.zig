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

pub fn deinit(self: *Memory) void {
    self.gpa.free(self.buf);
}

pub fn slice(self: *Memory, start: usize, size: usize) []u8 {
    if (size == 0) {
        return &[_]u8{};
    }

    const slice_size = @min(self.buf.len - start, size);
    return self.buf[start .. start + slice_size];
}

// Tries to grow the memory to fit the given region if there is enough gas
// Returns the remaning gas
pub fn growToFit(self: *Memory, offset: u256, size: u256, available_gas: i32) !i32 {
    if (size == 0) {
        return available_gas;
    }
    if (offset > std.math.maxInt(usize) or size > std.math.maxInt(usize)) {
        return evm.Errors.GasOverflow;
    }

    const off: usize = @intCast(offset);
    const sz: usize = @intCast(size);
    const mem_size, const overflown = @addWithOverflow(off, sz);
    if (overflown == 1) {
        return evm.Errors.GasOverflow;
    }

    const cost = 0; //todo: calculate
    if (cost > available_gas) {
        return evm.Errors.OutOfGas;
    }

    if (self.buf.len < mem_size) {
        if (self.buf.len == 0) {
            self.buf = try self.gpa.alloc(u8, mem_size);
        } else {
            if (!self.gpa.resize(self.buf, mem_size)) {
                return std.mem.Allocator.Error.OutOfMemory;
            }
            self.buf.len = mem_size;
        }
    }
    return available_gas - cost;
}

// Copies from source to the memory region given. Clears tail part of the memory region
// that wasn't filled if any
pub fn copyAndClearRemaining(self: *Memory, offset: usize, size: usize, source: []const u8) void {
    const destination = self.slice(offset, size);
    @memcpy(destination[0..source.len], source);
    @memset(destination[source.len..], 0);
}
