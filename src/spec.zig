const ops = @import("ops.zig");
const Opcode = @import("opcode.zig").Opcode;
const std = @import("std");

pub const Fork = enum(u8) {
    Osaka,
};

// Holds the constant information related to each hardfork
pub const Spec = struct {
    const Self = @This();

    fork: Fork,
    gas_table: [256]u32,

    // EIP-2929: access cost tiers
    warm_access_gas: i32,
    cold_account_access_gas: i32,
    cold_sload_gas: i32,

    // EIP-2200/3529: SSTORE gas schedule
    sstore_set_gas: i32,
    sstore_reset_gas: i32,
    sstore_clears_schedule: i32,

    // EIP-170: max deployed code size and deposit cost per byte
    max_code_size: usize,
    code_deposit_gas: usize,

    // EIP-2930: access list intrinsic gas
    access_list_address_gas: u31,
    access_list_storage_key_gas: u31,

    // Intrinsic base gas per transaction type
    tx_base_gas: u31,
    tx_create_gas: u31,

    // Per-word gas for hashing operations (KECCAK256, CREATE2)
    keccak_word_gas: i32,

    // EIP-150: denominator for the 63/64 gas forwarding rule
    gas_forward_denom: i32,

    selfdestruct_empty_target_gas: i32,

    // EIP-7623 TOTAL_COST_FLOOR_PER_TOKEN
    total_cost_floor_per_token: u31,

    // EIP-160: gas per byte of exponent in EXP
    exp_per_byte_gas: i32,

    // CALL gas constants
    call_value_gas: i32, // charged when CALL/CALLCODE sends non-zero value
    call_new_account_gas: i32, // charged when CALL creates a new (empty) account
    call_stipend: u31, // bonus gas given to callee when value is transferred

    pub fn constantGas(self: *const Self, comptime op: Opcode) i32 {
        return @intCast(self.gas_table[@intFromEnum(op)]);
    }
};

// Osaka hardfork spec
pub const Osaka = Spec{
    .fork = .Osaka,

    .warm_access_gas = 100,
    .cold_account_access_gas = 2600,
    .cold_sload_gas = 2100,

    .sstore_set_gas = 20000,
    .sstore_reset_gas = 2900,
    .sstore_clears_schedule = 4800,

    .max_code_size = 0x6000,
    .code_deposit_gas = 200,

    .access_list_address_gas = 2400,
    .access_list_storage_key_gas = 1900,

    .tx_base_gas = 21000,
    .tx_create_gas = 53000,

    .keccak_word_gas = 6,
    .gas_forward_denom = 64,

    .selfdestruct_empty_target_gas = 25000,

    .total_cost_floor_per_token = 10,

    .call_value_gas = 9000,
    .call_new_account_gas = 25000,
    .call_stipend = 2300,

    .exp_per_byte_gas = 50,

    .gas_table = std.enums.directEnumArrayDefault(Opcode, u32, 0, 256, .{
        .STOP = 0,
        .ADD = 3,
        .MUL = 5,
        .SUB = 3,
        .DIV = 5,
        .SDIV = 5,
        .MOD = 5,
        .SMOD = 5,
        .ADDMOD = 8,
        .MULMOD = 8,
        .EXP = 10,
        .SIGNEXTEND = 5,
        .LT = 3,
        .GT = 3,
        .SLT = 3,
        .SGT = 3,
        .EQ = 3,
        .ISZERO = 3,
        .AND = 3,
        .XOR = 3,
        .OR = 3,
        .NOT = 3,
        .BYTE = 3,
        .SHL = 3,
        .SHR = 3,
        .SAR = 3,
        .CLZ = 5,
        .KECCAK256 = 30,
        .ADDRESS = 2,
        .BALANCE = 0,
        .ORIGIN = 2,
        .CALLER = 2,
        .CALLVALUE = 2,
        .CALLDATALOAD = 3,
        .CALLDATASIZE = 2,
        .CALLDATACOPY = 3,
        .CODESIZE = 2,
        .CODECOPY = 3,
        .GASPRICE = 2,
        .EXTCODESIZE = 0,
        .EXTCODECOPY = 0,
        .RETURNDATASIZE = 2,
        .RETURNDATACOPY = 3,
        .EXTCODEHASH = 0,
        .BLOCKHASH = 20,
        .COINBASE = 2,
        .TIMESTAMP = 2,
        .NUMBER = 2,
        .PREVRANDO = 2,
        .GASLIMIT = 2,
        .CHAINID = 2,
        .SELFBALANCE = 5,
        .BASEFEE = 2,
        .BLOBHASH = 3,
        .BLOBBASEFEE = 2,
        .POP = 2,
        .MLOAD = 3,
        .MSTORE = 3,
        .MSTORE8 = 3,
        .SLOAD = 0,
        .SSTORE = 0,
        .JUMP = 8,
        .JUMPI = 10,
        .PC = 2,
        .MSIZE = 2,
        .GAS = 2,
        .JUMPDEST = 1,
        .TLOAD = 100,
        .TSTORE = 100,
        .MCOPY = 3,

        .PUSH0 = 2,
        .PUSH1 = 3,
        .PUSH2 = 3,
        .PUSH3 = 3,
        .PUSH4 = 3,
        .PUSH5 = 3,
        .PUSH6 = 3,
        .PUSH7 = 3,
        .PUSH8 = 3,
        .PUSH9 = 3,
        .PUSH10 = 3,
        .PUSH11 = 3,
        .PUSH12 = 3,
        .PUSH13 = 3,
        .PUSH14 = 3,
        .PUSH15 = 3,
        .PUSH16 = 3,
        .PUSH17 = 3,
        .PUSH18 = 3,
        .PUSH19 = 3,
        .PUSH20 = 3,
        .PUSH21 = 3,
        .PUSH22 = 3,
        .PUSH23 = 3,
        .PUSH24 = 3,
        .PUSH25 = 3,
        .PUSH26 = 3,
        .PUSH27 = 3,
        .PUSH28 = 3,
        .PUSH29 = 3,
        .PUSH30 = 3,
        .PUSH31 = 3,
        .PUSH32 = 3,

        .DUP1 = 3,
        .DUP2 = 3,
        .DUP3 = 3,
        .DUP4 = 3,
        .DUP5 = 3,
        .DUP6 = 3,
        .DUP7 = 3,
        .DUP8 = 3,
        .DUP9 = 3,
        .DUP10 = 3,
        .DUP11 = 3,
        .DUP12 = 3,
        .DUP13 = 3,
        .DUP14 = 3,
        .DUP15 = 3,
        .DUP16 = 3,

        .SWAP1 = 3,
        .SWAP2 = 3,
        .SWAP3 = 3,
        .SWAP4 = 3,
        .SWAP5 = 3,
        .SWAP6 = 3,
        .SWAP7 = 3,
        .SWAP8 = 3,
        .SWAP9 = 3,
        .SWAP10 = 3,
        .SWAP11 = 3,
        .SWAP12 = 3,
        .SWAP13 = 3,
        .SWAP14 = 3,
        .SWAP15 = 3,
        .SWAP16 = 3,

        .LOG0 = 375,
        .LOG1 = 375,
        .LOG2 = 375,
        .LOG3 = 375,
        .LOG4 = 375,

        .CREATE = 32000,
        .CALL = 0,
        .CALLCODE = 0,
        .RETURN = 0,
        .DELEGATECALL = 0,
        .CREATE2 = 32000,
        .STATICCALL = 0,
        .REVERT = 0,
        .SELFDESTRUCT = 5000,
    }),
};
