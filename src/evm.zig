const std = @import("std");
const ops = @import("ops.zig");
const spec = @import("spec.zig");
const storage = @import("storage.zig");
const precompile = @import("precompile.zig");
const Bytecode = @import("bytecode.zig").Bytecode;
const Memory = @import("memory.zig").Memory;
const State = @import("state.zig").State;
const Spec = spec.Spec;

const max_stack_size = 1024;
const empty_code_hash = @import("state.zig").empty_code_hash;
const empty_root_hash = @import("state.zig").empty_root_hash;
const isEmptyAccount = @import("state.zig").isEmptyAccount;

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
    PriorityFeeTooHigh,
    Reverted,
    WriteProtection,
    InitcodeSizeExceeded,
    SenderNotEOA,
    CreateBlobTx,
    ZeroBlobs,
    TooManyBlobs,
    InvalidBlobVersionedHash,
    InsufficientMaxFeePerBlobGas,
    EmptyAuthorizationList,
    CreateSetCodeTx,
    InvalidPrecompileInput,
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

    // EIP-4844
    excess_blob_gas: u64,
    max_blobs_per_block: u64,
    blob_base_fee_update_fraction: u64,
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

pub const AccessListEntry = struct {
    address: u160,
    storage_keys: []const u256,
};

pub const Authorization = struct {
    chain_id: u64,
    address: u160,
    nonce: u64,
    authority: u160,
};

pub const Message = struct {
    caller: u160,
    nonce: u64,
    target: ?u160, // null = CREATE, some(addr) = CALL (including to address 0)
    gas_limit: i32,
    gas_price: ?u256 = null, // legacy gas price; null for EIP-1559 txs
    calldata: []u8,
    value: u256,
    // EIP-1559
    max_fee_per_gas: ?u256 = null,
    max_priority_fee_per_gas: ?u256 = null,
    // EIP-2930: accounts and slots to pre-warm before execution
    access_list: []const AccessListEntry = &.{},
    // EIP-4844: non-null marks this as a type-3 blob tx
    max_fee_per_blob_gas: ?u256 = null,
    blob_versioned_hashes: []u256 = &.{},
    // EIP-7702: non-null marks this as a type-4 set-code tx
    authorization_list: ?[]const Authorization = null,
};

const Snapshot = struct {
    accounts: usize,
    slots: usize,
    gas_refund: i32,
    created: usize,
    num_logs: usize,
};

pub const Log = struct {
    address: u160,
    topics: []u256,
    data: []u8,
};

pub const EVM = struct {
    const Self = @This();

    gpa: std.mem.Allocator,
    msg: *const Message,
    context: *const Context,

    // LOG handling
    logs_allocator: std.mem.Allocator,
    logs: *std.DoublyLinkedList,
    num_logs: usize,

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
    // effective gas price for the current transaction
    effective_gas_price: u256,
    // Accounts created in this txn, also used to mark them for SELFDESTRUCT
    created_accounts: storage.CreatedAccounts,

    pub fn init(
        allocator: std.mem.Allocator,
        logs_allocator: std.mem.Allocator,
        logs: *std.DoublyLinkedList,
        msg: *const Message,
        context: *const Context,
    ) !Self {
        var pre_state: storage.SlotKeyedMap(u256) = .empty;
        try pre_state.ensureTotalCapacity(allocator, 10_000);
        return Self{
            .gpa = allocator,
            .msg = msg,
            .context = context,
            .return_buffer = try allocator.alloc(u8, 16 * 1024 * 1024),
            .return_data_size = 0,
            .pre_state = pre_state,
            .warm_accounts = try storage.AccountsAccessList.init(allocator, 10_000, 10_000),
            .warm_slots = try storage.SlotsAccessList.init(allocator, 10_000, 10_000),
            .gas_refund = 0,
            .effective_gas_price = effectiveGasPrice(msg, context.basefee),
            .created_accounts = try storage.CreatedAccounts.init(allocator, 1_000, 2_000),
            .logs_allocator = logs_allocator,
            .logs = logs,
            .num_logs = 0,
        };
    }

    pub fn snapshot(self: *Self) Snapshot {
        return .{
            .accounts = self.warm_accounts.snapshot(),
            .slots = self.warm_slots.snapshot(),
            .gas_refund = self.gas_refund,
            .created = self.created_accounts.snapshot(),
            .num_logs = self.num_logs,
        };
    }

    pub fn revert(self: *Self, snapshot_ids: Snapshot) void {
        self.warm_accounts.revert(snapshot_ids.accounts);
        self.warm_slots.revert(snapshot_ids.slots);
        self.gas_refund = snapshot_ids.gas_refund;
        self.created_accounts.revert(snapshot_ids.created);
        for (snapshot_ids.num_logs..self.num_logs) |_| self.popLog();
    }

    pub fn effectiveGasPrice(msg: *const Message, basefee: u256) u256 {
        const priority = msg.max_priority_fee_per_gas orelse 0;
        return if (msg.max_fee_per_gas) |mfpg|
            @min(mfpg, basefee + priority)
        else
            msg.gas_price orelse 0;
    }

    pub fn validateAndPriceBlobTx(self: *const Self, comptime fork: Spec, blob_base_fee: u256) !struct { i32, u256 } {
        const msg = self.msg;
        if (msg.max_fee_per_blob_gas) |max_fee_per_blob| {
            const hashes = msg.blob_versioned_hashes;
            if (msg.target == null) return Errors.CreateBlobTx;
            if (hashes.len == 0) return Errors.ZeroBlobs;
            if (hashes.len > fork.max_blobs_per_tx)
                return Errors.TooManyBlobs;
            if (hashes.len > self.context.max_blobs_per_block)
                return Errors.TooManyBlobs;
            for (hashes) |hash| {
                if (hash >> 248 != 0x01) return Errors.InvalidBlobVersionedHash;
            }
            if (max_fee_per_blob < blob_base_fee) return Errors.InsufficientMaxFeePerBlobGas;

            const gas = @as(i32, @intCast(hashes.len)) * fork.gas_per_blob;
            const upfront = std.math.mul(u256, @intCast(gas), max_fee_per_blob) catch return Errors.NotEnoughFunds;
            return .{ gas, upfront };
        }
        return .{ 0, 0 };
    }

    pub fn process(self: *Self, comptime fork: Spec, state: *State) !i32 {
        const msg = self.msg;

        if (self.effective_gas_price < self.context.basefee) {
            return Errors.FeeTooLow;
        }

        // EIP-1559: maxPriorityFeePerGas must not exceed maxFeePerGas
        if (msg.max_fee_per_gas) |mfpg| {
            if (msg.max_priority_fee_per_gas) |mpfpg| {
                if (mpfpg > mfpg) return Errors.PriorityFeeTooHigh;
            }
        }

        // tx gas limit must not exceed block gas limit
        if (msg.gas_limit > self.context.gas_limit) {
            return Errors.GasOverflow;
        }

        // EIP-7825: transaction gas limit cap
        if (msg.gas_limit > fork.max_tx_gas) {
            return Errors.GasOverflow;
        }

        const is_create = msg.target == null;

        // EIP-7702: type-4 transactions must have a non-empty authorization list and no CREATE
        if (msg.authorization_list) |al| {
            if (al.len == 0) return Errors.EmptyAuthorizationList;
            if (is_create) return Errors.CreateSetCodeTx;
        }

        // EIP-3860: reject CREATE transactions with oversized initcode before any state changes
        if (is_create and msg.calldata.len > 2 * fork.max_code_size) {
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

        // EIP-3607: reject transaction if sender has code (is a contract).
        // EIP-7702: relax this for accounts with a delegation designator — they remain EOAs.
        if (caller_account.code_hash != empty_code_hash) {
            const caller_code = state.code_storage.get(caller_account.code_hash);
            if (caller_code == null or !isDelegation(caller_code.?.bytes)) return Errors.SenderNotEOA;
        }

        // EIP-4844: blob transaction validation
        const blob_base_fee = blobBaseFee(self.context.excess_blob_gas, self.context.blob_base_fee_update_fraction);
        const blob_gas, const blob_upfront = try self.validateAndPriceBlobTx(fork, blob_base_fee);

        // EIP-1559: upfront balance check uses maxFeePerGas (worst-case gas cost) if set
        const balance_check_price = msg.max_fee_per_gas orelse self.effective_gas_price;
        const balance_check_cost = std.math.mul(u256, @intCast(msg.gas_limit), balance_check_price) catch return Errors.GasOverflow;
        const upfront_gas_cost = std.math.add(u256, balance_check_cost, blob_upfront) catch return Errors.NotEnoughFunds;
        const upfront_cost = std.math.add(u256, upfront_gas_cost, msg.value) catch return Errors.NotEnoughFunds;
        if (caller_account.balance < upfront_cost) {
            return Errors.NotEnoughFunds;
        }

        // For CALL txs, increment nonce here; for CREATE, create() handles nonce increment.
        if (!is_create) caller_account.nonce = msg.nonce + 1;
        const gas_cost = std.math.mul(u256, @intCast(msg.gas_limit), self.effective_gas_price) catch return Errors.GasOverflow;
        caller_account.balance -= gas_cost;
        // EIP-4844: deduct blob gas fee (non-refundable, uses actual base fee not max)
        caller_account.balance -= @as(u256, @intCast(blob_gas)) * blob_base_fee;

        const intrinsic_gas = if (is_create) fork.tx_create_gas else fork.tx_base_gas;
        const calldata_gas, const floor_data_cost = try calldataCost(fork, msg.calldata);
        const floor_cost = fork.tx_base_gas + floor_data_cost; // EIP-7623
        const access_list_gas = try accessListGas(fork, msg.access_list);
        // EIP-3860: 2 gas per 32-byte initcode word, charged as intrinsic for CREATE txs
        const initcode_gas = if (is_create) initcodeWordCost(msg.calldata.len) else 0;
        // EIP-7702: PER_EMPTY_ACCOUNT_COST per authorization tuple
        const auth_list_len: i32 = if (msg.authorization_list) |al| @intCast(al.len) else 0;
        const auth_gas = std.math.mul(i32, auth_list_len, fork.per_empty_account_cost) catch return Errors.OutOfGas;
        const total_intrinsic = intrinsic_gas + calldata_gas + access_list_gas + initcode_gas + auth_gas;
        if (msg.gas_limit < total_intrinsic or msg.gas_limit < floor_cost) {
            return Errors.OutOfGas;
        }
        const execution_gas_limit = msg.gas_limit - total_intrinsic;

        inline for (precompile.Handlers(fork).table(), 0..) |handler, addr| {
            if (handler) |_| {
                _ = self.accessAccount(addr);
            }
        }
        _ = self.accessAccount(self.context.coinbase); // EIP-3651
        self.applyAccessList(msg.access_list);

        // EIP-7702: process authorization list, setting delegation designators on EOAs
        if (msg.authorization_list) |auth_list|
            self.applyAuthList(fork, auth_list, state);

        var remaining_gas = execution_gas_limit;
        if (msg.target) |target| {
            _ = self.accessAccount(target);

            // EIP-7702: if destination has a delegation, add delegate to accessed_addresses
            const target_code_hash = state.accounts.read(target).code_hash;
            if (target_code_hash != empty_code_hash) {
                const code = state.code_storage.get(target_code_hash).?;
                if (isDelegation(code.bytes)) _ = self.accessAccount(delegationAddress(code.bytes));
            }

            remaining_gas, _ = self.call(
                fork,
                state,
                msg.caller,
                target,
                target,
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
        const max_refund = @divFloor(gas_used_before_refund, 5);
        const effective_refund = @min(@max(self.gas_refund, 0), max_refund);
        remaining_gas += effective_refund;
        self.gas_refund = 0;

        const gas_used_by_execution = msg.gas_limit - remaining_gas;
        if (gas_used_by_execution < floor_cost) {
            remaining_gas = msg.gas_limit - floor_cost;
        }

        state.accounts.update(msg.caller).balance += @as(u256, @intCast(remaining_gas)) * self.effective_gas_price;

        // EIP-1559: coinbase receives only the tip; the base fee is burned
        const tip = self.effective_gas_price - self.context.basefee;
        const gas_used = msg.gas_limit - remaining_gas;
        if (tip > 0) {
            state.accounts.update(self.context.coinbase).balance += @as(u256, @intCast(gas_used)) * tip;
        }
        return gas_used;
    }

    // Returns { remaining_gas, optional_error }. Not an error union because Reverted
    // must return remaining gas to the caller alongside the error signal.
    // skip_value_transfer: set true for DELEGATECALL, which preserves msg.value in the
    // sub-frame without actually moving ETH (the original transfer already happened).
    pub fn call(
        self: *Self,
        comptime fork: Spec,
        state: *State,
        caller: u160,
        target: u160,
        code_addr: u160,
        initial_gas: i32,
        calldata: []u8,
        value: u256,
        depth: usize,
        return_buffer: []u8,
        skip_value_transfer: bool,
        is_static: bool,
    ) struct { i32, ?Errors } {
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

        var remaining_gas, var err = .{ initial_gas, @as(?Errors, null) };
        if (fork.getPrecompile(code_addr)) |precompile_handler| {
            remaining_gas, err = self.callPrecompile(
                precompile_handler,
                initial_gas,
                calldata,
                return_buffer,
            );
        } else if (resolveCode(code_addr, state)) |code| {
            var frame = self.gpa.create(Frame) catch unreachable;
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
                .is_static = is_static,
                .return_buffer = return_buffer,

                .gas = initial_gas,
                .stack = undefined,
                .memory = Memory.init(self.gpa),
                .depth = depth + 1,
            };
            defer frame.memory.deinit();

            frame.enter() catch |frameErr| {
                err = frameErr;
            };
            remaining_gas = frame.gas;
        }

        if (err != null) {
            if (err.? != Errors.Reverted) {
                remaining_gas = 0;
                // OOG and other non-revert failures leave no return data
                self.return_data_size = 0;
            }
            state.revert(state_snap);
            self.revert(evm_snap);
        }
        return .{ remaining_gas, err };
    }

    // EIP-7702: return the EIP-2929 access cost for following a delegation on code_addr, also
    // marking the delegate as warm. Returns 0 if code_addr has no delegation designator.
    // Must be called from CALL/CALLCODE/DELEGATECALL/STATICCALL before forwarding gas.
    pub fn delegationAccessCost(self: *Self, comptime fork: Spec, code_addr: u160, state: *State) i32 {
        const code_hash = state.accounts.read(code_addr).code_hash;
        if (code_hash == empty_code_hash) return 0;
        const raw = state.code_storage.get(code_hash) orelse return 0;
        if (!isDelegation(raw.bytes)) return 0;
        return self.accessAccountCost(fork, delegationAddress(raw.bytes));
    }

    pub fn callPrecompile(
        self: *Self,
        handler: precompile.Handler,
        initial_gas: i32,
        calldata: []u8,
        return_buffer: []u8,
    ) struct { i32, ?Errors } {
        const result = handler(initial_gas, calldata, self.return_buffer);
        self.return_data_size = result.return_size;
        if (result.return_size > 0) {
            const copy_len = @min(result.return_size, return_buffer.len);
            @memcpy(return_buffer[0..copy_len], self.return_buffer[0..copy_len]);
        }
        return .{ result.remaining_gas, result.err };
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
        initial_gas: i32,
        depth: usize,
        salt: ?u256,
    ) struct { i32, u160 } {
        // Depth/nonce/balance failures are "never started" — return all forwarded gas to caller.
        if (depth >= 1024) return .{ initial_gas, 0 };

        const creator_account = state.accounts.read(creator);
        const nonce = creator_account.nonce;
        // Nonce must not overflow (u64 range enforced at tx entry; sub-calls inherit that invariant)
        if (nonce >= std.math.maxInt(u64)) return .{ initial_gas, 0 };
        if (creator_account.balance < value) return .{ initial_gas, 0 };

        const new_addr: u160 = if (salt) |s|
            create2Address(creator, s, initcode)
        else
            createAddress(creator, @intCast(nonce));

        // EIP-2929: warm the new address
        _ = self.accessAccount(new_addr);

        // Increase creator nonce before the snapshot
        var creator_acc = state.accounts.update(creator);
        creator_acc.nonce += 1;

        // Return data is always cleared when CREATE is entered, even on collision failure
        self.return_data_size = 0;

        // EIP-7610: fail on collision (non-zero nonce or existing code or existing storage)
        const existing = state.accounts.read(new_addr);
        if (existing.nonce != 0 or existing.code_hash != empty_code_hash or existing.storage_hash != empty_root_hash) return .{ 0, 0 };

        const state_snap = state.snapshot();
        const evm_snap = self.snapshot();

        // Commit value transfer
        creator_acc = state.accounts.update(creator);
        creator_acc.balance -= value;
        const new_contract_acc = state.accounts.update(new_addr);
        new_contract_acc.nonce = 1; // EIP-161
        new_contract_acc.balance += value;

        // Compile and execute initcode
        const initcode_bytecode = Bytecode.init(self.gpa, initcode, fork) catch unreachable;
        defer initcode_bytecode.deinit(self.gpa);
        var frame = self.gpa.create(Frame) catch unreachable;
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
            if (err != Errors.Reverted) {
                frame.gas = 0;
                self.return_data_size = 0;
            }
            state.revert(state_snap);
            self.revert(evm_snap);
            return .{ frame.gas, 0 };
        };

        // Collect deployed bytecode from the global return buffer
        const deployed_len = self.return_data_size;
        self.return_data_size = 0;
        const deployed_code = self.return_buffer[0..deployed_len];
        const deposit_gas: i32 = @intCast(deployed_len * fork.code_deposit_gas);

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
            state.deploy_code(code_hash, deployed_code, fork);
        }
        state.accounts.update(new_addr).code_hash = code_hash;
        // created_accounts was registered before frame.enter(); SELFDESTRUCT may have marked it false — don't overwrite.
        return .{ frame.gas, new_addr };
    }

    pub const LogNode = struct { log: Log, node: std.DoublyLinkedList.Node };

    pub fn pushLog(self: *Self, address: u160, topics: []const u256, data: []const u8) void {
        const ln = self.logs_allocator.create(LogNode) catch unreachable;
        ln.* = LogNode{ .log = .{
            .address = address,
            .topics = self.logs_allocator.dupe(u256, topics) catch unreachable,
            .data = self.logs_allocator.dupe(u8, data) catch unreachable,
        }, .node = .{} };
        self.logs.append(&ln.node);
        self.num_logs += 1;
    }

    pub fn popLog(self: *Self) void {
        if (self.logs.pop()) |node| {
            const ln: *LogNode = @alignCast(@fieldParentPtr("node", node));
            // make sure to free in the reverse of the order they were allocated
            self.logs_allocator.free(ln.log.data);
            self.logs_allocator.free(ln.log.topics);
            self.logs_allocator.destroy(ln);
            self.num_logs -= 1;
        }
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

    // EIP-7702: process authorization list, setting delegation designators on EOAs
    pub fn applyAuthList(self: *Self, comptime fork: Spec, auth_list: []const Authorization, state: *State) void {
        for (auth_list) |auth| {
            // Skip if authority is zero (invalid signature recovery)
            if (auth.authority == 0) continue;
            // Skip if chain_id is non-zero and doesn't match current chain
            if (auth.chain_id != 0 and auth.chain_id != self.context.chainid) continue;
            // EIP-7702 step 2: nonce in the tuple must be < 2**64-1
            if (auth.nonce >= std.math.maxInt(u64)) continue;
            _ = self.accessAccount(auth.authority);
            const auth_account = state.accounts.read(auth.authority);
            // Skip if authority already has non-delegation code
            if (auth_account.code_hash != empty_code_hash) {
                const existing = state.code_storage.get(auth_account.code_hash).?;
                if (!isDelegation(existing.bytes)) continue;
            }
            // Skip if nonce doesn't match
            if (auth_account.nonce != auth.nonce) continue;
            // Refund if account is non-empty (already had state)
            if (!isEmptyAccount(&auth_account)) {
                self.gas_refund += fork.per_empty_account_cost - fork.per_auth_base_cost;
            }
            var auth_mutable = state.accounts.update(auth.authority);
            if (auth.address == 0) {
                // Reset: remove delegation, restore empty code hash
                auth_mutable.code_hash = empty_code_hash;
            } else {
                const dg_hash = delegationCodeHash(auth.address);
                if (state.code_storage.get(dg_hash) == null) {
                    const dg_code = delegationCode(auth.address);
                    state.deploy_code(dg_hash, &dg_code, fork);
                }
                auth_mutable.code_hash = dg_hash;
            }
            auth_mutable.nonce += 1;
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

// EIP-7702: resolve delegation designator one level deep. Pure lookup with no gas side effects.
fn resolveCode(code_addr: u160, state: *State) ?Bytecode {
    const code_hash = state.accounts.read(code_addr).code_hash;
    if (code_hash == empty_code_hash) return null;
    const raw = state.code_storage.get(code_hash).?;
    if (!isDelegation(raw.bytes)) return raw;
    const dh = state.accounts.read(delegationAddress(raw.bytes)).code_hash;
    return state.code_storage.get(dh);
}

// EIP-3860: 2 gas per 32-byte initcode word (ceiling division)
fn initcodeWordCost(len: usize) i32 {
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

fn accessListGas(comptime fork: Spec, access_list: []const AccessListEntry) !i32 {
    var gas: i32 = 0;
    for (access_list) |entry| {
        gas = std.math.add(i32, gas, fork.access_list_address_gas) catch return Errors.OutOfGas;
        const key_gas = std.math.mul(usize, entry.storage_keys.len, fork.access_list_storage_key_gas) catch return Errors.OutOfGas;
        gas = std.math.add(i32, gas, @intCast(key_gas)) catch return Errors.OutOfGas;
    }
    return gas;
}

fn calldataCost(comptime fork: Spec, calldata: []u8) !struct { i32, i32 } {
    const zeros = std.mem.count(u8, calldata, &[_]u8{0});
    const cost = zeros * 4 + (calldata.len - zeros) * 16;
    const tokens = zeros + (calldata.len - zeros) * 4;
    const floor = std.math.mul(usize, tokens, fork.total_cost_floor_per_token) catch return Errors.OutOfGas;
    if (cost > std.math.maxInt(i32) or floor > std.math.maxInt(i32)) {
        return Errors.OutOfGas;
    }
    return .{ @intCast(cost), @intCast(floor) };
}

pub fn blobBaseFee(excess_blob_gas: u64, update_fraction: u64) u256 {
    if (update_fraction == 0) return 1;
    // fake_exponential(1, excess_blob_gas, update_fraction)
    const denom: u256 = update_fraction;
    var i: u256 = 1;
    var output: u256 = 0;
    var accum: u256 = denom; // factor(1) * denominator
    while (accum > 0) {
        output += accum;
        accum = accum * excess_blob_gas / (denom * i);
        i += 1;
    }
    return output / denom;
}

// EIP-7702: delegation designator prefix (0xef0100) followed by 20-byte address = 23 bytes total
const delegation_prefix = [3]u8{ 0xef, 0x01, 0x00 };

fn isDelegation(bytes: []const u8) bool {
    return bytes.len == 23 and std.mem.startsWith(u8, bytes, &delegation_prefix);
}

fn delegationAddress(bytes: []const u8) u160 {
    return std.mem.readInt(u160, bytes[3..23], .big);
}

fn delegationCode(address: u160) [23]u8 {
    var buf: [23]u8 = undefined;
    buf[0..3].* = delegation_prefix;
    std.mem.writeInt(u160, buf[3..23], address, .big);
    return buf;
}

fn delegationCodeHash(address: u160) u256 {
    const code = delegationCode(address);
    var hash: [32]u8 = undefined;
    std.crypto.hash.sha3.Keccak256.hash(&code, &hash, .{});
    return std.mem.readInt(u256, &hash, .big);
}
