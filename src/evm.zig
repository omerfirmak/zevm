const std = @import("std");
const ops = @import("ops.zig");
const spec = @import("spec.zig");
const storage = @import("storage.zig");
const Bytecode = @import("bytecode.zig").Bytecode;
const Memory = @import("memory.zig").Memory;
const State = @import("state.zig").State;
const Spec = spec.Spec;

const max_stack_size = 1024;
const empty_code_hash = @import("state.zig").empty_code_hash;
const empty_root_hash = @import("state.zig").empty_root_hash;

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
    WriteProtection,
    InitcodeSizeExceeded,
};

pub const Context = struct {
    chainid: u64,

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
    is_static: bool,
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

pub const AccessListEntry = struct {
    address: u160,
    storage_keys: []const u256,
};

pub const Message = struct {
    caller: u160,
    nonce: u64,
    target: u160,
    gas_limit: u31,
    gas_price: u256,
    calldata: []u8,
    value: u256,
    // EIP-2930: accounts and slots to pre-warm before execution
    access_list: []const AccessListEntry = &.{},
};

const Snapshot = struct {
    accounts: usize,
    slots: usize,
    gas_refund: i32,
    created: usize,
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
    // EIP-2200/EIP-3529: accumulated gas refund counter; may go negative mid-tx
    gas_refund: i32,
    // jump table used to compile initcode during CREATE/CREATE2
    jump_table: *const [256]ops.FnOpaquePtr,
    // Accounts created in this txn, also used to mark them for SELFDESTRUCT
    created_accounts: storage.CreatedAccounts,

    pub fn init(allocator: std.mem.Allocator, context: *const Context, jump_table: *const [256]ops.FnOpaquePtr) !Self {
        var pre_state: storage.SlotKeyedMap(u256) = .empty;
        try pre_state.ensureTotalCapacity(allocator, 10_000);
        var self = Self{
            .gpa = allocator,
            .context = context,
            .return_buffer = try allocator.alloc(u8, 16 * 1024 * 1024),
            .return_data_size = 0,
            .pre_state = pre_state,
            .warm_accounts = try storage.AccountsAccessList.init(allocator, 10_000, 10_000),
            .warm_slots = try storage.SlotsAccessList.init(allocator, 10_000, 10_000),
            .gas_refund = 0,
            .jump_table = jump_table,
            .created_accounts = try storage.CreatedAccounts.init(allocator, 1_000, 2_000),
        };
        _ = self.accessAccount(context.coinbase); // EIP-3651
        return self;
    }

    pub fn snapshot(self: *Self) Snapshot {
        return .{
            .accounts = self.warm_accounts.snapshot(),
            .slots = self.warm_slots.snapshot(),
            .gas_refund = self.gas_refund,
            .created = self.created_accounts.snapshot(),
        };
    }

    pub fn revert(self: *Self, snapshot_ids: Snapshot) void {
        self.warm_accounts.revert(snapshot_ids.accounts);
        self.warm_slots.revert(snapshot_ids.slots);
        self.gas_refund = snapshot_ids.gas_refund;
        self.created_accounts.revert(snapshot_ids.created);
    }

    pub fn process(self: *Self, comptime fork: Spec, msg: Message, state: *State) !void {
        if (msg.gas_price < self.context.basefee) {
            return Errors.FeeTooLow;
        }

        // EIP-7825: transaction gas limit cap
        if (msg.gas_limit > fork.max_tx_gas) {
            return Errors.GasOverflow;
        }

        // EIP-3860: reject CREATE transactions with oversized initcode before any state changes
        if (msg.target == 0 and msg.calldata.len > 2 * fork.max_code_size) {
            return Errors.InitcodeSizeExceeded;
        }

        _ = self.accessAccount(msg.caller);
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
        if (msg.target != 0) caller_account.nonce = msg.nonce + 1;
        caller_account.balance -= gas_cost;

        const intrinsic_gas: u31 = if (msg.target == 0) fork.tx_create_gas else fork.tx_base_gas;
        const calldata_gas, const floor_data_cost = try calldataCost(fork, msg.calldata);
        const floor_cost = fork.tx_base_gas + floor_data_cost; // EIP-7623
        const access_list_gas = try accessListGas(fork, msg.access_list);
        // EIP-3860: 2 gas per 32-byte initcode word, charged as intrinsic for CREATE txs
        const initcode_gas: u31 = if (msg.target == 0) initcodeWordCost(msg.calldata.len) else 0;
        const total_intrinsic = intrinsic_gas + calldata_gas + access_list_gas + initcode_gas;
        if (msg.gas_limit < total_intrinsic or msg.gas_limit < floor_cost) {
            return Errors.OutOfGas;
        }
        const execution_gas_limit = msg.gas_limit - total_intrinsic;

        self.applyAccessList(msg.access_list);

        var remaining_gas = execution_gas_limit;
        if (msg.target != 0) {
            _ = self.accessAccount(msg.target);
            const target_code_hash = state.accounts.read(msg.target).code_hash;
            const code = state.code_storage.get(target_code_hash);
            remaining_gas, _ = self.call(
                state,
                msg.caller,
                msg.target,
                code,
                remaining_gas,
                msg.calldata,
                msg.value,
                0,
                &[_]u8{},
                false,
                false,
            );
        } else {
            remaining_gas, _ = self.create(
                fork,
                state,
                msg.caller,
                msg.calldata,
                msg.value,
                remaining_gas,
                0,
                null,
            );
        }

        // EIP-3529: refund capped at 1/5 of total gas used (intrinsic + execution)
        const gas_used_before_refund = msg.gas_limit - remaining_gas;
        const max_refund = gas_used_before_refund / 5;
        const effective_refund: u31 = @intCast(@min(@max(self.gas_refund, 0), max_refund));
        remaining_gas += effective_refund;
        self.gas_refund = 0;

        const gas_used_by_execution = msg.gas_limit - remaining_gas;
        if (gas_used_by_execution < floor_cost) {
            remaining_gas = msg.gas_limit - floor_cost;
        }

        state.accounts.update(msg.caller).balance += @as(u256, @intCast(remaining_gas)) * msg.gas_price;

        // EIP-1559: coinbase receives only the tip; the base fee is burned
        const tip = msg.gas_price - self.context.basefee;
        const gas_used: u256 = msg.gas_limit - remaining_gas;
        if (tip > 0) {
            state.accounts.update(self.context.coinbase).balance += gas_used * tip;
        }
    }

    // Returns { remaining_gas, optional_error }. Not an error union because Reverted
    // must return remaining gas to the caller alongside the error signal.
    // skip_value_transfer: set true for DELEGATECALL, which preserves msg.value in the
    // sub-frame without actually moving ETH (the original transfer already happened).
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
        skip_value_transfer: bool,
        is_static: bool,
    ) struct { u31, ?Errors } {
        if (depth >= 1024) return .{ initial_gas, Errors.CallDepthExceeded };

        const state_snap = state.snapshot();
        const evm_snap = self.snapshot();

        self.return_data_size = 0;
        if (!skip_value_transfer) {
            var caller_account = state.accounts.update(caller);
            if (caller_account.balance < value) {
                return .{ initial_gas, Errors.NotEnoughFunds };
            }
            caller_account.balance -= value;
            if (value > 0) {
                state.accounts.update(target).balance += value;
            }
        }

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
            .is_static = is_static,
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

    // Returns { remaining_gas, new_address }. Address is 0 on any failure.
    // Failures are never propagated — the caller pushes 0 instead of an address.
    pub fn create(
        self: *Self,
        comptime fork: Spec,
        state: *State,
        creator: u160,
        initcode: []const u8,
        value: u256,
        initial_gas: u31,
        depth: usize,
        salt: ?u256,
    ) struct { u31, u160 } {
        if (depth >= 1024) return .{ 0, 0 };

        const creator_account = state.accounts.read(creator);
        const nonce = creator_account.nonce;
        // Nonce must not overflow (u64 range enforced at tx entry; sub-calls inherit that invariant)
        if (nonce >= std.math.maxInt(u64)) return .{ 0, 0 };
        if (creator_account.balance < value) return .{ 0, 0 };

        const new_addr: u160 = if (salt) |s|
            create2Address(creator, s, initcode)
        else
            createAddress(creator, @intCast(nonce));

        // EIP-2929: warm the new address
        _ = self.accessAccount(new_addr);

        // Increase creator nonce before the snapshot
        var creator_acc = state.accounts.update(creator);
        creator_acc.nonce += 1;

        // EIP-7610: fail on collision (non-zero nonce or existing code or existing storage)
        const existing = state.accounts.read(new_addr);
        if (existing.nonce != 0 or existing.code_hash != empty_code_hash or existing.storage_hash != empty_root_hash) return .{ 0, 0 };

        const state_snap = state.snapshot();
        const evm_snap = self.snapshot();
        self.return_data_size = 0;

        // Commit value transfer
        creator_acc = state.accounts.update(creator);
        creator_acc.balance -= value;
        const new_contract_acc = state.accounts.update(new_addr);
        new_contract_acc.nonce = 1; // EIP-161
        new_contract_acc.balance += value;

        // Compile and execute initcode
        const initcode_bytecode = Bytecode.init(self.gpa, initcode, @ptrCast(self.jump_table)) catch @panic("OutOfMemory");
        defer initcode_bytecode.deinit(self.gpa);
        var frame = self.gpa.create(Frame) catch @panic("OutOfMemory");
        defer self.gpa.destroy(frame);
        frame.* = Frame{
            .evm = self,
            .context = self.context,
            .state = state,
            .code = initcode_bytecode,
            .caller = creator,
            .target = new_addr,
            .calldata = &[_]u8{},
            .value = value,
            .is_static = false,
            .return_buffer = &[_]u8{}, // RETURN will write to self.return_buffer anyways
            .gas = initial_gas,
            .stack = undefined,
            .memory = Memory.init(self.gpa),
            .depth = depth + 1,
        };
        defer frame.memory.deinit();

        // Register before execution so SELFDESTRUCT in initcode can mark it destroyed.
        // Use write() (journaled) so the caller's revert can undo this entry if needed.
        _ = self.created_accounts.write(new_addr, .Created);
        frame.enter() catch |err| {
            if (err != Errors.Reverted) frame.gas = 0;
            state.revert(state_snap);
            self.revert(evm_snap);
            return .{ frame.gas, 0 };
        };

        // Collect deployed bytecode from the global return buffer
        const deployed_len = self.return_data_size;
        self.return_data_size = 0;
        const deployed_code = self.return_buffer[0..deployed_len];
        const deposit_gas: u31 = @intCast(deployed_len * fork.code_deposit_gas);

        if (deployed_len > fork.max_code_size or // EIP-170
            (deployed_len > 0 and deployed_code[0] == 0xef) or // EIP-3541: reject EOF containers (0xEF prefix) in non-EOF deployments
            frame.gas < deposit_gas) // Charge code deposit gas
        {
            state.revert(state_snap);
            self.revert(evm_snap);
            return .{ 0, 0 };
        }
        frame.gas -= deposit_gas;

        // Store deployed code and update account code hash
        var code_hash: u256 = empty_code_hash;
        if (deployed_len > 0) {
            var hash: [32]u8 = undefined;
            std.crypto.hash.sha3.Keccak256.hash(deployed_code, &hash, .{});
            code_hash = std.mem.readInt(u256, &hash, .big);
            state.deploy_code(code_hash, deployed_code, self.jump_table);
        }
        state.accounts.update(new_addr).code_hash = code_hash;
        // created_accounts was registered before frame.enter(); SELFDESTRUCT may have marked it false — don't overwrite.
        return .{ frame.gas, new_addr };
    }

    pub fn accessAccount(self: *Self, addr: u160) bool {
        return !self.warm_accounts.writeNoClobber(addr, {});
    }

    pub fn accessAccountCost(self: *Self, comptime fork: Spec, addr: u160) i32 {
        return if (self.accessAccount(addr)) fork.warm_access_gas else fork.cold_account_access_gas;
    }

    pub fn accessSlot(self: *Self, addr: u160, slot: u256) bool {
        return !self.warm_slots.writeNoClobber(.{ .address = addr, .slot = slot }, {});
    }

    pub fn accessSlotCost(self: *Self, comptime fork: Spec, addr: u160, slot: u256) i32 {
        return if (self.accessSlot(addr, slot)) fork.warm_access_gas else fork.cold_sload_gas;
    }

    // EIP-2930: pre-warm all addresses and storage keys in the access list
    pub fn applyAccessList(self: *Self, access_list: []const AccessListEntry) void {
        for (access_list) |entry| {
            _ = self.accessAccount(entry.address);
            for (entry.storage_keys) |key| {
                _ = self.accessSlot(entry.address, key);
            }
        }
    }

    pub fn markForDestruction(self: *Self, addr: u160) bool {
        if (self.created_accounts.dirties.getEntry(addr)) |_| {
            _ = self.created_accounts.write(addr, .Selfdestructed);
            return true;
        }
        return false;
    }
};

// EIP-3860: 2 gas per 32-byte initcode word (ceiling division)
fn initcodeWordCost(len: usize) u31 {
    return @intCast(((len + 31) / 32) * 2);
}

/// CREATE address: keccak256(rlp([creator, nonce]))[12:]
// RLP([address, nonce]): max 1 (list) + 21 (addr) + 9 (nonce) = 31 bytes
fn createAddress(creator: u160, nonce: u64) u160 {
    var buf: [31]u8 = undefined;
    var pos: usize = 1; // reserve buf[0] for list prefix

    // address: 0x94 (0x80+20) || 20 bytes big-endian
    buf[pos] = 0x94;
    pos += 1;
    std.mem.writeInt(u160, buf[pos..][0..20], creator, .big);
    pos += 20;

    // nonce: 0x80 for zero, single byte for 1-127, length-prefixed otherwise
    if (nonce == 0) {
        buf[pos] = 0x80;
        pos += 1;
    } else if (nonce < 0x80) {
        buf[pos] = @intCast(nonce);
        pos += 1;
    } else {
        var tmp: [8]u8 = undefined;
        std.mem.writeInt(u64, &tmp, nonce, .big);
        var start: usize = 0;
        while (start < 7 and tmp[start] == 0) start += 1;
        const nonce_bytes = tmp[start..];
        buf[pos] = @intCast(0x80 + nonce_bytes.len);
        pos += 1;
        @memcpy(buf[pos..][0..nonce_bytes.len], nonce_bytes);
        pos += nonce_bytes.len;
    }

    buf[0] = @intCast(0xc0 + (pos - 1)); // list prefix: 0xc0 + payload_len

    var hash: [32]u8 = undefined;
    std.crypto.hash.sha3.Keccak256.hash(buf[0..pos], &hash, .{});
    return std.mem.readInt(u160, hash[12..32], .big);
}

// CREATE2 address: keccak256(0xff ++ creator ++ salt ++ keccak256(initcode))[12:]
fn create2Address(creator: u160, salt: u256, initcode: []const u8) u160 {
    var buf: [85]u8 = undefined;
    buf[0] = 0xff;
    std.mem.writeInt(u160, buf[1..21], creator, .big);
    std.mem.writeInt(u256, buf[21..53], salt, .big);
    std.crypto.hash.sha3.Keccak256.hash(initcode, buf[53..85], .{});
    var hash: [32]u8 = undefined;
    std.crypto.hash.sha3.Keccak256.hash(&buf, &hash, .{});
    return std.mem.readInt(u160, hash[12..32], .big);
}

fn accessListGas(comptime fork: Spec, access_list: []const AccessListEntry) !u31 {
    var gas: u31 = 0;
    for (access_list) |entry| {
        gas = std.math.add(u31, gas, fork.access_list_address_gas) catch return Errors.OutOfGas;
        const key_gas = std.math.mul(usize, entry.storage_keys.len, fork.access_list_storage_key_gas) catch return Errors.OutOfGas;
        gas = std.math.add(u31, gas, @intCast(key_gas)) catch return Errors.OutOfGas;
    }
    return gas;
}

fn calldataCost(comptime fork: Spec, calldata: []u8) !struct { u31, u31 } {
    const zeros = std.mem.count(u8, calldata, &[_]u8{0});
    const cost = zeros * 4 + (calldata.len - zeros) * 16;
    const tokens = zeros + (calldata.len - zeros) * 4;
    const floor = std.math.mul(usize, tokens, fork.total_cost_floor_per_token) catch return Errors.OutOfGas;
    if (cost > std.math.maxInt(u31) or floor > std.math.maxInt(u31)) {
        return Errors.OutOfGas;
    }
    return .{ @intCast(cost), @intCast(floor) };
}
