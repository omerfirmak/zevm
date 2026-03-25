const std = @import("std");
const ops = @import("ops.zig");
const spec = @import("spec.zig");
const storage = @import("storage.zig");
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
    FeeTooLow,
    Reverted,
};

pub const Context = struct {
    // Block level context
    number: u64,
    coinbase: u160,
    time: u64,
    random: u256,
    basefee: u256,
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
    // caller-provided slice where sub-call return data is written
    return_buffer: []u8,

    // vm state
    // u31 fits within i32 without sign collision, so gas arithmetic in ops can use i32
    gas: u31,
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
    gas_limit: u31,
    gas_price: u256,
    calldata: []u8,
    value: u256,
};

const Snapshot = struct {
    accounts: usize,
    slots: usize,
};

pub const EVM = struct {
    const Self = @This();

    gpa: std.mem.Allocator,
    context: *const Context,

    // global return data buffer shared across all call frames; size tracks valid bytes
    return_buffer: []u8,
    return_data_size: usize,

    // original storage values before any writes this tx; used for EIP-2200 SSTORE gas
    pre_state: storage.SlotKeyedMap(u256),
    // EIP-2929 access lists; warm slots/accounts pay lower gas on subsequent access
    warm_accounts: storage.AccountsAccessList,
    warm_slots: storage.SlotsAccessList,

    pub fn init(allocator: std.mem.Allocator, context: *const Context) !Self {
        var pre_state: storage.SlotKeyedMap(u256) = .empty;
        try pre_state.ensureTotalCapacity(allocator, 10_000);
        return Self{
            .gpa = allocator,
            .context = context,
            .return_buffer = try allocator.alloc(u8, 16 * 1024 * 1024),
            .return_data_size = 0,
            .pre_state = pre_state,
            .warm_accounts = try storage.AccountsAccessList.init(allocator, 10_000, 10_000),
            .warm_slots = try storage.SlotsAccessList.init(allocator, 10_000, 10_000),
        };
    }

    pub fn snapshot(self: *Self) Snapshot {
        return .{
            .accounts = self.warm_accounts.snapshot(),
            .slots = self.warm_slots.snapshot(),
        };
    }

    pub fn revert(self: *Self, snapshot_ids: Snapshot) void {
        self.warm_accounts.revert(snapshot_ids.accounts);
        self.warm_slots.revert(snapshot_ids.slots);
    }

    pub fn process(self: *Self, msg: Message, state: *State) !void {
        if (msg.gas_price < self.context.basefee) {
            return Errors.FeeTooLow;
        }

        var caller_account = state.accounts.update(msg.caller);
        if (caller_account.nonce < msg.nonce) {
            return Errors.NonceTooLow;
        } else if (caller_account.nonce > msg.nonce) {
            return Errors.NonceTooHigh;
        } else if (msg.nonce == std.math.maxInt(u64)) {
            return Errors.NonceMax;
        }

        const gas_cost = std.math.mul(u256, @intCast(msg.gas_limit), msg.gas_price) catch return Errors.NotEnoughFunds;
        if (caller_account.balance < gas_cost) {
            return Errors.NotEnoughFunds;
        }
        caller_account.nonce = msg.nonce + 1;
        caller_account.balance -= gas_cost;

        // base gas cost: 21000 for calls, 32000 for contract creation
        const intrinsic_gas: u31 = if (msg.target) |_| 21000 else 32000;
        const calldata_gas = try calldataCost(msg.calldata);
        if (msg.gas_limit < (intrinsic_gas + calldata_gas)) {
            return Errors.OutOfGas;
        }
        const gas_limit = msg.gas_limit - intrinsic_gas - @as(u31, @intCast(calldata_gas));

        // todo: contract creation
        const target = msg.target.?;
        var remaining_gas = gas_limit;
        const target_code_hash = state.accounts.read(target).code_hash;
        const code = state.code_storage.get(target_code_hash);
        remaining_gas, _ = self.call(
            state,
            msg.caller,
            target,
            code,
            remaining_gas,
            msg.calldata,
            msg.value,
            0,
            &[_]u8{},
        );

        state.accounts.update(msg.caller).balance += @as(u256, @intCast(remaining_gas)) * msg.gas_price;

        // EIP-1559: coinbase receives only the tip; the base fee is burned
        const tip = msg.gas_price - self.context.basefee;
        const gas_used: u256 = msg.gas_limit - remaining_gas;
        state.accounts.update(self.context.coinbase).balance += gas_used * tip;
    }

    // Returns { remaining_gas, optional_error }. Not an error union because Reverted
    // must return remaining gas to the caller alongside the error signal.
    pub fn call(
        self: *Self,
        state: *State,
        caller: u160,
        target: u160,
        code: ?Bytecode,
        initial_gas: u31,
        calldata: []u8,
        value: u256,
        depth: usize,
        return_buffer: []u8,
    ) struct { u31, ?Errors } {
        if (depth >= 1024) return .{ initial_gas, Errors.CallDepthExceeded };

        const state_snap = state.snapshot();
        const evm_snap = self.snapshot();

        self.return_data_size = 0;
        var caller_account = state.accounts.update(caller);
        if (caller_account.balance < value) {
            return .{ initial_gas, Errors.NotEnoughFunds };
        }
        caller_account.balance -= value;
        state.accounts.update(target).balance += value;

        if (code == null) {
            return .{ initial_gas, null };
        }

        var frame = self.gpa.create(Frame) catch @panic("OutOfMemory");
        defer self.gpa.destroy(frame);
        frame.* = Frame{
            .evm = self,
            .context = self.context,
            .state = state,
            .code = code.?,

            .caller = caller,
            .target = target,
            .calldata = calldata,
            .value = value,
            .return_buffer = return_buffer,

            .gas = initial_gas,
            .stack = undefined,
            .memory = Memory.init(self.gpa),
            .depth = depth + 1,
        };
        defer frame.memory.deinit();

        frame.enter() catch |err| {
            if (err != Errors.Reverted) {
                frame.gas = 0;
            }
            state.revert(state_snap);
            self.revert(evm_snap);
            return .{ frame.gas, err };
        };
        return .{ frame.gas, null };
    }

    pub fn accessAccount(self: *Self, addr: u160) bool {
        return !self.warm_accounts.writeNoClobber(addr, {});
    }

    pub fn accessSlot(self: *Self, addr: u160, slot: u256) bool {
        return !self.warm_slots.writeNoClobber(.{ .address = addr, .slot = slot }, {});
    }
};

fn calldataCost(calldata: []u8) !u31 {
    const zeros = std.mem.count(u8, calldata, &[_]u8{0});
    const cost = zeros * 4 + (calldata.len - zeros) * 16;
    if (cost > std.math.maxInt(u31)) {
        return Errors.OutOfGas;
    }
    return @intCast(cost);
}
