const std = @import("std");
const ops = @import("ops.zig");
const spec = @import("spec.zig");
const Bytecode = @import("bytecode.zig").Bytecode;
const Memory = @import("memory.zig").Memory;
const State = @import("state.zig").State;

const max_stack_size = 1024;
const empty_code_hash = @import("state.zig").empty_code_hash;

pub const Errors = error{
    OutOfGas,
    InvalidOpcode,
    StackOverflow,
    StackUnderflow,
    InvalidJumpDest,
    GasOverflow,
    NonceTooLow,
    NonceTooHigh,
    NonceMax,
    NotEnoughFunds,
    ReturnDataOutOfBounds,
    CallDepthExceeded,
} || std.mem.Allocator.Error;

pub const Context = struct {
    // Block level context
    number: u64,
    coinbase: u160,
    time: u64,
    random: u256,
    gas_limit: u64,

    // Tx level context
    from: u160,
    gas_price: u256,
};

pub const Frame = struct {
    const Self = @This();

    evm: *EVM,
    context: *const Context,
    state: *State,
    code: Bytecode,

    // call context
    caller: u160,
    target: u160,
    calldata: []const u8,
    value: u256,
    depth: usize,
    return_buffer: []u8,

    // vm state
    gas: i32,
    stack: [max_stack_size]u256 align(@sizeOf(u256)),
    memory: Memory,

    pub fn enter(self: *Self) !void {
        const entry_op: ops.Fn = @ptrCast(self.code.threaded_code[0]);
        return entry_op(self.code.threaded_code[1..].ptr, self.gas, 0, self);
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
        if (head == max_stack_size) {
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

pub const Message = struct {
    caller: u160,
    nonce: u64,
    target: ?u160,
    gas_limit: u64,
    calldata: []u8,
    value: u256,
};

pub const EVM = struct {
    const Self = @This();

    gpa: std.mem.Allocator,
    context: *const Context,

    return_buffer: []u8,
    return_data_size: usize,

    pub fn init(allocator: std.mem.Allocator, context: *const Context) !Self {
        return Self{
            .gpa = allocator,
            .context = context,
            .return_buffer = try allocator.alloc(u8, 16 * 1024 * 1024),
            .return_data_size = 0,
        };
    }

    pub fn process(self: *Self, msg: Message, state: *State) !void {
        var caller_account = state.accounts.update(msg.caller);
        if (caller_account.nonce < msg.nonce) {
            return Errors.NonceTooLow;
        } else if (caller_account.nonce > msg.nonce) {
            return Errors.NonceTooHigh;
        } else if (msg.nonce == std.math.maxInt(u64)) {
            return Errors.NonceMax;
        }

        var gas_cost = std.math.mul(u256, @intCast(msg.gas_limit), self.context.gas_price) catch return Errors.NotEnoughFunds;
        if (caller_account.balance < gas_cost) {
            return Errors.NotEnoughFunds;
        }
        caller_account.nonce = msg.nonce + 1;
        caller_account.balance -= gas_cost;
        defer {
            state.accounts.update(self.context.coinbase).balance += gas_cost;
        }

        // todo: contract creation
        const target = msg.target.?;
        var target_account = state.accounts.update(target);
        target_account.balance += msg.value;
        if (target_account.code_hash != empty_code_hash) {
            const code = state.code_storage.get(target_account.code_hash).?;
            const remaining_gas = try self.call(
                state,
                msg.caller,
                target,
                code,
                @intCast(msg.gas_limit),
                msg.calldata,
                msg.value,
                0,
                &[_]u8{},
            );

            const refund = remaining_gas * self.context.gas_price;
            state.accounts.update(msg.caller).balance += refund;
            gas_cost -= refund;
        }
        return;
    }

    pub fn call(
        self: *Self,
        state: *State,
        caller: u160,
        target: u160,
        code: Bytecode,
        initial_gas: i32,
        calldata: []u8,
        value: u256,
        depth: usize,
        return_buffer: []u8,
    ) !u64 {
        if (depth >= 1024) return Errors.CallDepthExceeded;

        self.return_data_size = 0;
        var caller_account = state.accounts.update(caller);
        if (caller_account.balance < value) {
            return Errors.NotEnoughFunds;
        }
        caller_account.balance -= value;

        var frame = try self.gpa.create(Frame);
        defer self.gpa.destroy(frame);
        frame.* = Frame{
            .evm = self,
            .context = self.context,
            .state = state,
            .code = code,

            .caller = caller,
            .target = target,
            .calldata = calldata,
            .value = value,
            .return_buffer = return_buffer,

            .gas = initial_gas,
            .stack = undefined,
            .memory = try Memory.init(self.gpa),
            .depth = depth + 1,
        };
        defer frame.memory.deinit();

        try frame.enter();
        return @intCast(frame.gas);
    }
};
