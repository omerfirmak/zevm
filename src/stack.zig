const evm = @import("evm.zig");
const std = @import("std");

const MaxStackSize = 1024;

// EVM Stack implementation
pub const Stack = @This();

data: [MaxStackSize]u256 align(@sizeOf(u256)) = undefined,
head: u16 = 0,

// Pushes the given value on top of the stack
// Errors out if the stack is full
pub fn push(self: *Stack, v: u256) !void {
    const slot = try self.reserve();
    slot.* = v;
    return;
}

// Reserves the slot on stack and returns a pointer to it.
// Errors out if the stack is full
pub fn reserve(self: *Stack) !*u256 {
    if (self.head == MaxStackSize) {
        @branchHint(.cold);
        return evm.Errors.StackOverflow;
    }
    self.head += 1;
    return &self.data[self.head - 1];
}

// Returns `n` items from the top of the stack. Also allows last `peek` number
// of items to be peeked in-place.
pub fn pop(self: *Stack, n: comptime_int, peek: comptime_int) !*[n]u256 {
    comptime std.debug.assert(n >= peek);

    if (self.head < n) {
        @branchHint(.cold);
        return evm.Errors.StackUnderflow;
    }
    self.head -= n - peek;
    return @ptrCast(self.data[self.head - peek .. self.head + n - peek].ptr);
}

test "push/pop" {
    const testing = @import("std").testing;

    var s = Stack{ .data = undefined, .head = 0 };
    try testing.expectError(evm.Errors.StackUnderflow, s.pop(1, 0));
    for (0..MaxStackSize) |elem| {
        try s.push(elem);
    }

    try testing.expectError(evm.Errors.StackOverflow, s.push(0));
    for (0..MaxStackSize) |_| {
        _ = try s.pop(1, 0);
    }
    try testing.expectError(evm.Errors.StackUnderflow, s.pop(1, 0));
}
