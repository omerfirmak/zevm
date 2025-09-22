const std = @import("std");
const ops = @import("ops.zig");
const spec = @import("spec.zig");
const Bytecode = @import("bytecode.zig").Bytecode;
const Memory = @import("memory.zig").Memory;

const MaxStackSize = 1024;

pub const Errors = error{
    OutOfGas,
    InvalidOpcode,
    StackOverflow,
    StackUnderflow,
    InvalidJumpDest,
    GasOverflow,
};

pub const Context = struct {
    // Block level context
    number: u64,
    coinbase: u160,
    time: u64,
    difficulty: u256,
    gas_limit: u64,
};

pub const Frame = struct {
    const Self = @This();

    context: *const Context,
    value: u256,
    gas: i32,
    bytecode: Bytecode,
    stack: [MaxStackSize]u256 align(@sizeOf(u256)),
    memory: Memory,
    calldata: []const u8,

    pub fn safeSliceCalldata(self: *Self, index: u256, size: u64) []const u8 {
        if (index >= self.calldata.len) {
            return &[_]u8{};
        }
        const read_size = @min(self.calldata.len - index, size);
        return self.calldata[@intCast(index)..@intCast(index + read_size)];
    }

    // Pushes the given value on top of the stack
    // Errors out if the stack is full
    pub fn stackPush(self: *Self, head: u16, v: u256) !u16 {
        const newHead, const slot = try self.stackReserve(head);
        slot.* = v;
        return newHead;
    }

    // Reserves the slot on stack and returns a pointer to it.
    // Errors out if the stack is full
    pub fn stackReserve(self: *Self, head: u16) !struct { u16, *u256 } {
        if (head == MaxStackSize) {
            @branchHint(.cold);
            return Errors.StackOverflow;
        }
        return .{ head + 1, &self.stack[head] };
    }

    // Returns `n` items from the top of the stack. Also allows last `peek` number
    // of items to be peeked in-place.
    pub fn stackPop(self: *Self, head: u16, n: comptime_int, peek: comptime_int) !struct { u16, *[n]u256 } {
        comptime std.debug.assert(n >= peek);

        if (head < n) {
            @branchHint(.cold);
            return Errors.StackUnderflow;
        }
        return .{ head - n + peek, @ptrCast(self.stack[head - n .. head].ptr) };
    }
};

pub const EVM = struct {
    const Self = @This();

    gpa: std.mem.Allocator,
    context: *const Context,

    pub fn init(allocator: std.mem.Allocator, context: *const Context) !Self {
        return Self{
            .gpa = allocator,
            .context = context,
        };
    }

    pub fn run(self: *Self, target: Bytecode, initial_gas: i32, calldata: []u8, value: u256) !void {
        // todo: move this to an arena
        var frame = Frame{
            .context = self.context,
            .value = value,
            .gas = initial_gas,
            .bytecode = target,
            .stack = undefined,
            .memory = try Memory.init(self.gpa),
            .calldata = calldata,
        };

        const entry_op: ops.Fn = @ptrCast(frame.bytecode.threaded_code[0]);
        return entry_op(target.threaded_code[1..].ptr, frame.gas, 0, &frame);
    }
};
