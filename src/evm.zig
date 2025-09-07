const std = @import("std");
const ops = @import("ops.zig");
const spec = @import("spec.zig");
const Bytecode = @import("bytecode.zig").Bytecode;
const Stack = @import("stack.zig").Stack;
const Memory = @import("memory.zig").Memory;

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
    gasLimit: u64,
};

pub const Frame = struct {
    const Self = @This();

    context: *const Context,
    value: u256,
    gas: i32,
    bytecode: Bytecode,
    stack: Stack,
    memory: Memory,
    calldata: []const u8,

    pub fn safeSliceCalldata(self: *Self, index: u256, size: u64) []const u8 {
        if (index >= self.calldata.len) {
            return &[_]u8{};
        }
        const readSize = @min(self.calldata.len - index, size);
        return self.calldata[@intCast(index)..@intCast(index + readSize)];
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

    pub fn run(self: *Self, target: Bytecode, initialGas: i32, calldata: []u8, value: u256) !void {
        // todo: move this to an arena
        var frame = Frame{
            .context = self.context,
            .value = value,
            .gas = initialGas,
            .bytecode = target,
            .stack = .{},
            .memory = try Memory.init(self.gpa),
            .calldata = calldata,
        };

        const entryOp: ops.Fn = @ptrCast(frame.bytecode.threadedCode[0]);
        defer std.debug.print("{any} \n", .{frame.stack.data[0..frame.stack.head]});
        return entryOp(target.threadedCode[1..].ptr, frame.gas, &frame);
    }
};
