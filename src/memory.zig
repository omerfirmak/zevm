const std = @import("std");
const evm = @import("evm.zig");

pub const Memory = @This();

const max_mem_size = std.math.sqrt(std.math.maxInt(usize)) * 32;

gpa: std.mem.Allocator,
costSoFar: usize,
buf: []u8,

pub fn init(gpa: std.mem.Allocator) !Memory {
    return Memory{
        .gpa = gpa,
        .costSoFar = 0,
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
    const mem_size = std.math.add(usize, off, sz) catch return evm.Errors.GasOverflow;
    if (mem_size > max_mem_size) return evm.Errors.GasOverflow;

    const mem_words = (mem_size + 31) / 32;
    const padded_mem_size = mem_words * 32;
    var cost: usize = 0;
    if (self.buf.len < padded_mem_size) {
        cost = mem_words * mem_words / 512 + 3 * mem_words - self.costSoFar;
        if (cost > available_gas) {
            return evm.Errors.OutOfGas;
        }

        if (self.buf.len == 0) {
            self.buf = try self.gpa.alloc(u8, padded_mem_size);
        } else {
            if (!self.gpa.resize(self.buf, padded_mem_size)) {
                return std.mem.Allocator.Error.OutOfMemory;
            }
            self.buf.len = padded_mem_size;
        }
    }

    self.costSoFar += cost;
    return available_gas - @as(i32, @intCast(cost));
}

// Copies from source to the memory region given. Clears tail part of the memory region
// that wasn't filled if any
pub fn copyAndClearRemaining(self: *Memory, offset: usize, size: usize, source: []const u8) void {
    const destination = self.slice(offset, size);
    @memcpy(destination[0..source.len], source);
    @memset(destination[source.len..], 0);
}
