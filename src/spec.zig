const ops = @import("ops.zig");
const Opcode = @import("opcode.zig").Opcode;
const std = @import("std");

pub const Fork = enum(u8) {
    Frontier,
    Homestead,
};

// Holds the constant information related to each hardfork
pub const Spec = struct {
    const Self = @This();

    fork: Fork,
    gasTable: [256]u64,

    pub fn constantGas(self: *const Self, comptime op: Opcode) i64 {
        return @intCast(self.gasTable[@intFromEnum(op)]);
    }
};

// Frontier hardfork spec
pub const Frontier = Spec{
    .fork = .Frontier,
    .gasTable = std.enums.directEnumArrayDefault(Opcode, u64, 0, 256, .{
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
        .KECCAK256 = 30,
        .ADDRESS = 2,
        .BALANCE = 20,
        .ORIGIN = 2,
        .CALLER = 2,
        .CALLVALUE = 2,
        .CALLDATALOAD = 3,
        .CALLDATASIZE = 2,
        .CALLDATACOPY = 3,
        .CODESIZE = 2,
        .CODECOPY = 3,
        .GASPRICE = 2,
        .EXTCODESIZE = 20,
        .EXTCODECOPY = 20,
        .BLOCKHASH = 20,
        .COINBASE = 2,
        .TIMESTAMP = 2,
        .NUMBER = 2,
        .DIFFICULTY = 2,
        .GASLIMIT = 2,
        .POP = 2,
        .MLOAD = 3,
        .MSTORE = 3,
        .MSTORE8 = 3,
        .SLOAD = 50,
        .JUMP = 8,
        .JUMPI = 10,
        .PC = 2,
        .MSIZE = 2,
        .GAS = 2,
        .JUMPDEST = 1,

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

        .CREATE = 32000,
        .CALL = 40,
        .CALLCODE = 40,
    }),
};

fn makeHomesteadSpec(frontierSpec: Spec) Spec {
    var homesteadSpec = frontierSpec;
    homesteadSpec.fork = .Homestead;
    homesteadSpec.gasTable[@intFromEnum(Opcode.ADD)] = 40;
    return homesteadSpec;
}

pub const Homestead = makeHomesteadSpec(Frontier);
