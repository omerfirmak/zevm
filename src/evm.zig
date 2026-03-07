const std = @import("std");
const ops = @import("ops.zig");
const spec = @import("spec.zig");
const Bytecode = @import("bytecode.zig").Bytecode;
const Memory = @import("memory.zig").Memory;
const State = @import("state.zig").State;

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
    random: u256,
    gas_limit: u64,
};

pub const Frame = struct {
    const Self = @This();

    context: *const Context,
    state: *State,
    bytecode: Bytecode,

    // call context
    caller: u160,
    target: u160,
    calldata: []const u8,
    value: u256,
    depth: usize,

    // vm state
    gas: i32,
    stack: [MaxStackSize]u256 align(@sizeOf(u256)),
    memory: Memory,

    pub fn enter(self: *Self) !void {
        const entry_op: ops.Fn = @ptrCast(self.bytecode.threaded_code[0]);
        return entry_op(self.bytecode.threaded_code[1..].ptr, self.gas, 0, self);
    }

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

    pub fn call(self: *Self, state: *State, caller: u160, target: u160, code: Bytecode, initial_gas: i32, calldata: []u8, value: u256, depth: usize) !void {
        var frame = try self.gpa.create(Frame);
        defer self.gpa.destroy(frame);
        const memory = try Memory.init(self.gpa);
        defer frame.memory.deinit();

        frame.* = Frame{
            .context = self.context,
            .state = state,
            .bytecode = code,

            .caller = caller,
            .target = target,
            .calldata = calldata,
            .value = value,

            .gas = initial_gas,
            .stack = undefined,
            .memory = memory,
            .depth = depth + 1,
        };

        return frame.enter();
    }
};
