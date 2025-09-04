const std = @import("std");
const evm = @import("evm.zig");
const stack = @import("stack.zig");
const mem = @import("memory.zig");
const Opcode = @import("opcode.zig").Opcode;
const Bytecode = @import("bytecode.zig").Bytecode;
const Spec = @import("spec.zig").Spec;

// Type erased pointer to an opcode handler
// Used to circumvent shortcomings of Zig type system
pub const FnOpaquePtr = *align(@alignOf(usize)) const anyopaque;
const InstructionPointer = Bytecode.InstructionPointer;

// The interface that opcode handlers are required to implement
pub const Fn = *const fn (
    InstructionPointer,
    i64,
    *evm.Frame,
) evm.Errors!void;

// Returns implementations of opcodes for a given spec
pub fn Ops(comptime spec: Spec) type {
    return struct {
        // Tail calls the next instruction after checking to see if the execution has run out of gas
        // Increments the PC as well
        pub inline fn next(nextIP: InstructionPointer, gas: i64, frame: *evm.Frame) evm.Errors!void {
            if (gas < 0) {
                @branchHint(.unlikely);
                return evm.Errors.OutOfGas;
            }
            // It is safe to unwrap unconditionally here, jumpdest analysis should protect against a
            // null function pointer here.
            const nextOp: Fn = @ptrCast(nextIP[0].?);
            return @call(.always_tail, nextOp, .{ nextIP + 1, gas, frame });
        }

        pub fn invalid(_: InstructionPointer, _: i64, _: *evm.Frame) evm.Errors!void {
            return evm.Errors.InvalidOpcode;
        }

        pub fn stop(_: InstructionPointer, gas: i64, frame: *evm.Frame) evm.Errors!void {
            // I would rather just return this instead of writing it to the frame
            // but https://github.com/ziglang/zig/issues/18189
            frame.gas = gas;
            return;
        }

        pub fn pop(nextIP: InstructionPointer, gas: i64, frame: *evm.Frame) evm.Errors!void {
            _ = try frame.stack.pop(1, 0);
            return next(nextIP, gas - spec.constantGas(.POP), frame);
        }

        pub fn add(nextIP: InstructionPointer, gas: i64, frame: *evm.Frame) evm.Errors!void {
            const args = try frame.stack.pop(2, 1);
            args[0] = args[1] +% args[0];
            return next(nextIP, gas - spec.constantGas(.ADD), frame);
        }

        pub fn mul(nextIP: InstructionPointer, gas: i64, frame: *evm.Frame) evm.Errors!void {
            const args = try frame.stack.pop(2, 1);
            args[0] = args[1] *% args[0];
            return next(nextIP, gas - spec.constantGas(.MUL), frame);
        }

        pub fn sub(nextIP: InstructionPointer, gas: i64, frame: *evm.Frame) evm.Errors!void {
            const args = try frame.stack.pop(2, 1);
            args[0] = args[1] -% args[0];
            return next(nextIP, gas - spec.constantGas(.SUB), frame);
        }

        pub fn div(nextIP: InstructionPointer, gas: i64, frame: *evm.Frame) evm.Errors!void {
            const args = try frame.stack.pop(2, 1);
            args[0] = if (args[0] == 0) 0 else args[1] / args[0];
            return next(nextIP, gas - spec.constantGas(.DIV), frame);
        }

        pub fn sdiv(nextIP: InstructionPointer, gas: i64, frame: *evm.Frame) evm.Errors!void {
            const args = try frame.stack.pop(2, 1);
            args[0] = @bitCast(@divTrunc(@as(i256, @bitCast(args[1])), @as(i256, @bitCast(args[0]))));
            return next(nextIP, gas - spec.constantGas(.SDIV), frame);
        }

        pub fn mod(nextIP: InstructionPointer, gas: i64, frame: *evm.Frame) evm.Errors!void {
            const args = try frame.stack.pop(2, 1);
            args[0] = if (args[0] == 0) 0 else @mod(args[1], args[0]);
            return next(nextIP, gas - spec.constantGas(.MOD), frame);
        }

        pub fn smod(nextIP: InstructionPointer, gas: i64, frame: *evm.Frame) evm.Errors!void {
            const args = try frame.stack.pop(2, 1);
            args[0] = if (args[0] == 0) 0 else @bitCast(@mod(@as(i256, @bitCast(args[1])), @as(i256, @bitCast(args[0]))));
            return next(nextIP, gas - spec.constantGas(.SMOD), frame);
        }

        pub fn addmod(nextIP: InstructionPointer, gas: i64, frame: *evm.Frame) evm.Errors!void {
            const args = try frame.stack.pop(3, 1);
            args[0] = if (args[0] == 0) 0 else @intCast(@mod(@as(u257, args[2]) + @as(u257, args[1]), args[0]));
            return next(nextIP, gas - spec.constantGas(.ADDMOD), frame);
        }

        pub fn mulmod(nextIP: InstructionPointer, gas: i64, frame: *evm.Frame) evm.Errors!void {
            const args = try frame.stack.pop(3, 1);
            args[0] = if (args[0] == 0) 0 else @intCast(@mod(@as(u512, args[2]) * @as(u512, args[1]), args[0]));
            return next(nextIP, gas - spec.constantGas(.MULMOD), frame);
        }

        pub fn exp(nextIP: InstructionPointer, gas: i64, frame: *evm.Frame) evm.Errors!void {
            const args = try frame.stack.pop(2, 1);
            args[0] = std.math.pow(u256, args[1], args[0]);
            return next(nextIP, gas - spec.constantGas(.EXP), frame);
        }

        pub fn signextend(nextIP: InstructionPointer, gas: i64, frame: *evm.Frame) evm.Errors!void {
            const args = try frame.stack.pop(2, 1);
            if (args[1] <= 30) {
                const size: u5 = @intCast(args[1]);
                switch (size) {
                    inline 0...30 => |bytes| {
                        const bitSize = (@as(u16, bytes) + 1) * 8;
                        const truncated: std.meta.Int(.unsigned, bitSize) = @truncate(args[0]);
                        const truncatedSigned: std.meta.Int(.signed, bitSize) = @bitCast(truncated);
                        const extendedSigned: i256 = @intCast(truncatedSigned);
                        args[0] = @bitCast(extendedSigned);
                    },
                    else => unreachable,
                }
            }
            return next(nextIP, gas - spec.constantGas(.SIGNEXTEND), frame);
        }

        pub fn lt(nextIP: InstructionPointer, gas: i64, frame: *evm.Frame) evm.Errors!void {
            const args = try frame.stack.pop(2, 1);
            args[0] = @intFromBool(args[1] < args[0]);
            return next(nextIP, gas - spec.constantGas(.LT), frame);
        }

        pub fn gt(nextIP: InstructionPointer, gas: i64, frame: *evm.Frame) evm.Errors!void {
            const args = try frame.stack.pop(2, 1);
            args[0] = @intFromBool(args[1] > args[0]);
            return next(nextIP, gas - spec.constantGas(.GT), frame);
        }

        pub fn slt(nextIP: InstructionPointer, gas: i64, frame: *evm.Frame) evm.Errors!void {
            const args = try frame.stack.pop(2, 1);
            args[0] = @intFromBool(@as(i256, @bitCast(args[1])) < @as(i256, @bitCast(args[0])));
            return next(nextIP, gas - spec.constantGas(.SLT), frame);
        }

        pub fn sgt(nextIP: InstructionPointer, gas: i64, frame: *evm.Frame) evm.Errors!void {
            const args = try frame.stack.pop(2, 1);
            args[0] = @intFromBool(@as(i256, @bitCast(args[1])) > @as(i256, @bitCast(args[0])));
            return next(nextIP, gas - spec.constantGas(.SGT), frame);
        }

        pub fn eq(nextIP: InstructionPointer, gas: i64, frame: *evm.Frame) evm.Errors!void {
            const args = try frame.stack.pop(2, 1);
            args[0] = @intFromBool(args[1] == args[0]);
            return next(nextIP, gas - spec.constantGas(.EQ), frame);
        }

        pub fn iszero(nextIP: InstructionPointer, gas: i64, frame: *evm.Frame) evm.Errors!void {
            const args = try frame.stack.pop(1, 1);
            args[0] = @intFromBool(args[0] == 0);
            return next(nextIP, gas - spec.constantGas(.ISZERO), frame);
        }

        pub fn @"and"(nextIP: InstructionPointer, gas: i64, frame: *evm.Frame) evm.Errors!void {
            const args = try frame.stack.pop(2, 1);
            args[0] = args[1] & args[0];
            return next(nextIP, gas - spec.constantGas(.AND), frame);
        }

        pub fn @"or"(nextIP: InstructionPointer, gas: i64, frame: *evm.Frame) evm.Errors!void {
            const args = try frame.stack.pop(2, 1);
            args[0] = args[1] | args[0];
            return next(nextIP, gas - spec.constantGas(.OR), frame);
        }

        pub fn xor(nextIP: InstructionPointer, gas: i64, frame: *evm.Frame) evm.Errors!void {
            const args = try frame.stack.pop(2, 1);
            args[0] = args[1] ^ args[0];
            return next(nextIP, gas - spec.constantGas(.XOR), frame);
        }

        pub fn not(nextIP: InstructionPointer, gas: i64, frame: *evm.Frame) evm.Errors!void {
            const args = try frame.stack.pop(1, 1);
            args[0] = ~args[0];
            return next(nextIP, gas - spec.constantGas(.NOT), frame);
        }

        pub fn byte(nextIP: InstructionPointer, gas: i64, frame: *evm.Frame) evm.Errors!void {
            const args = try frame.stack.pop(2, 1);
            if (args[1] > 31) {
                args[0] = 0;
            } else {
                const index: u5 = @intCast(args[1]);
                args[0] = @as(u8, @intCast(args[0] >> (index * 8)));
            }
            return next(nextIP, gas - spec.constantGas(.BYTE), frame);
        }

        pub fn jumpdest(nextIP: InstructionPointer, gas: i64, frame: *evm.Frame) evm.Errors!void {
            return next(nextIP, gas - spec.constantGas(.JUMPDEST), frame);
        }

        pub fn jump(_: InstructionPointer, gas: i64, frame: *evm.Frame) evm.Errors!void {
            const args = try frame.stack.pop(1, 0);
            const jumpDest = frame.bytecode.isValidJumpDest(args[0]) orelse return evm.Errors.InvalidJumpDest;
            return next(jumpDest, gas - spec.constantGas(.JUMP), frame);
        }

        pub fn jumpi(nextIP: InstructionPointer, gas: i64, frame: *evm.Frame) evm.Errors!void {
            const args = try frame.stack.pop(2, 0);
            if (args[0] == 0) {
                return next(nextIP, gas - spec.constantGas(.JUMPI), frame);
            }

            const jumpDest = frame.bytecode.isValidJumpDest(args[1]) orelse return evm.Errors.InvalidJumpDest;
            return next(jumpDest, gas - spec.constantGas(.JUMPI), frame);
        }

        pub fn opGas(nextIP: InstructionPointer, gas: i64, frame: *evm.Frame) evm.Errors!void {
            try frame.stack.push(@intCast(gas));
            return next(nextIP, gas - spec.constantGas(.GAS), frame);
        }

        pub fn pushN(comptime n: usize) Fn {
            return struct {
                pub fn push(nextIP: InstructionPointer, gas: i64, frame: *evm.Frame) evm.Errors!void {
                    const stackSlot = try frame.stack.reserve();
                    frame.bytecode.readBytesToValue(nextIP, n, stackSlot);
                    return next(nextIP + n, gas - spec.constantGas(@enumFromInt(@intFromEnum(Opcode.PUSH0) + n)), frame);
                }
            }.push;
        }

        pub fn dupN(comptime n: usize) Fn {
            return struct {
                pub fn dup(nextIP: InstructionPointer, gas: i64, frame: *evm.Frame) evm.Errors!void {
                    const s = try frame.stack.pop(n, n);
                    try frame.stack.push(s[0]);
                    return next(nextIP, gas - spec.constantGas(@enumFromInt(@intFromEnum(Opcode.DUP1) + n - 1)), frame);
                }
            }.dup;
        }

        pub fn swapN(comptime n: usize) Fn {
            return struct {
                pub fn swap(nextIP: InstructionPointer, gas: i64, frame: *evm.Frame) evm.Errors!void {
                    const s = try frame.stack.pop(n + 1, n + 1);
                    const tmp = s[0];
                    s[0] = s[n];
                    s[n] = tmp;
                    return next(nextIP, gas - spec.constantGas(@enumFromInt(@intFromEnum(Opcode.SWAP1) + n - 1)), frame);
                }
            }.swap;
        }

        pub fn callvalue(nextIP: InstructionPointer, gas: i64, frame: *evm.Frame) evm.Errors!void {
            try frame.stack.push(frame.value);
            return next(nextIP, gas - spec.constantGas(.CALLVALUE), frame);
        }

        pub fn calldataload(nextIP: InstructionPointer, gas: i64, frame: *evm.Frame) evm.Errors!void {
            const args = try frame.stack.pop(1, 1);
            if (args[0] > frame.calldata.len) {
                args[0] = 0;
            } else {
                const index: usize = @intCast(args[0]);
                const end = @min(frame.calldata.len, index + 32);
                args[0] = std.mem.readVarInt(u256, frame.calldata[index..end], .big);
            }
            return next(nextIP, gas - spec.constantGas(.CALLDATALOAD), frame);
        }

        pub fn calldatasize(nextIP: InstructionPointer, gas: i64, frame: *evm.Frame) evm.Errors!void {
            try frame.stack.push(@intCast(frame.calldata.len));
            return next(nextIP, gas - spec.constantGas(.CALLDATASIZE), frame);
        }

        pub fn calldatacopy(nextIP: InstructionPointer, gas: i64, frame: *evm.Frame) evm.Errors!void {
            const args = try frame.stack.pop(3, 0);
            const availableGas = gas - try frame.memory.growToFit(args[2], args[0], gas);

            const calldata = frame.safeSliceCalldata(args[1], @intCast(args[0]));
            frame.memory.copyAndClearRemaining(@intCast(args[2]), @intCast(args[0]), calldata);
            return next(nextIP, availableGas - spec.constantGas(.CALLDATACOPY), frame);
        }

        pub fn codesize(nextIP: InstructionPointer, gas: i64, frame: *evm.Frame) evm.Errors!void {
            try frame.stack.push(frame.bytecode.bytecode.len);
            return next(nextIP, gas - spec.constantGas(.CODESIZE), frame);
        }

        pub fn codecopy(nextIP: InstructionPointer, gas: i64, frame: *evm.Frame) evm.Errors!void {
            const args = try frame.stack.pop(3, 0);
            const availableGas = gas - try frame.memory.growToFit(args[2], args[0], gas);

            const bytecode = frame.bytecode.safeSlice(args[1], @intCast(args[0]));
            frame.memory.copyAndClearRemaining(@intCast(args[2]), @intCast(args[0]), bytecode);
            return next(nextIP, availableGas - spec.constantGas(.CODECOPY), frame);
        }

        pub fn pc(nextIP: InstructionPointer, gas: i64, frame: *evm.Frame) evm.Errors!void {
            try frame.stack.push(frame.bytecode.programCounter(nextIP) - 1);
            return next(nextIP, gas - spec.constantGas(.PC), frame);
        }

        pub fn keccak256(nextIP: InstructionPointer, gas: i64, frame: *evm.Frame) evm.Errors!void {
            const args = try frame.stack.pop(2, 1);
            const availableGas = gas - try frame.memory.growToFit(args[1], args[0], gas);

            const data = frame.memory.slice(@intCast(args[1]), @intCast(args[0]));
            std.crypto.hash.sha3.Keccak256.hash(data, @ptrCast(&args[0]), .{});
            return next(nextIP, availableGas - spec.constantGas(.KECCAK256), frame);
        }

        pub fn msize(nextIP: InstructionPointer, gas: i64, frame: *evm.Frame) evm.Errors!void {
            try frame.stack.push(frame.memory.buf.len);
            return next(nextIP, gas - spec.constantGas(.MSIZE), frame);
        }

        pub fn coinbase(nextIP: InstructionPointer, gas: i64, frame: *evm.Frame) evm.Errors!void {
            try frame.stack.push(frame.context.coinbase);
            return next(nextIP, gas - spec.constantGas(.COINBASE), frame);
        }

        pub fn timestamp(nextIP: InstructionPointer, gas: i64, frame: *evm.Frame) evm.Errors!void {
            try frame.stack.push(frame.context.time);
            return next(nextIP, gas - spec.constantGas(.TIMESTAMP), frame);
        }

        pub fn number(nextIP: InstructionPointer, gas: i64, frame: *evm.Frame) evm.Errors!void {
            try frame.stack.push(frame.context.number);
            return next(nextIP, gas - spec.constantGas(.NUMBER), frame);
        }

        pub fn difficulty(nextIP: InstructionPointer, gas: i64, frame: *evm.Frame) evm.Errors!void {
            try frame.stack.push(frame.context.difficulty);
            return next(nextIP, gas - spec.constantGas(.DIFFICULTY), frame);
        }

        pub fn gaslimit(nextIP: InstructionPointer, gas: i64, frame: *evm.Frame) evm.Errors!void {
            try frame.stack.push(frame.context.gasLimit);
            return next(nextIP, gas - spec.constantGas(.GASLIMIT), frame);
        }

        // Constructs a jump table for the given spec
        pub fn table() [256]Fn {
            var t = std.enums.directEnumArrayDefault(Opcode, Fn, invalid, 256, .{
                .STOP = stop,
                .ADD = add,
                .MUL = mul,
                .SUB = sub,
                .DIV = div,
                .SDIV = sdiv,
                .POP = pop,
                .MOD = mod,
                .SMOD = smod,
                .ADDMOD = addmod,
                .MULMOD = mulmod,
                .SIGNEXTEND = signextend,
                .LT = lt,
                .GT = gt,
                .SLT = slt,
                .SGT = sgt,
                .EQ = eq,
                .ISZERO = iszero,
                .AND = @"and",
                .OR = @"or",
                .XOR = xor,
                .NOT = not,
                .BYTE = byte,
                .JUMPDEST = jumpdest,
                .JUMP = jump,
                .JUMPI = jumpi,
                .GAS = opGas,
                .CALLVALUE = callvalue,
                .CALLDATALOAD = calldataload,
                .CALLDATASIZE = calldatasize,
                .CALLDATACOPY = calldatacopy,
                .CODESIZE = codesize,
                .CODECOPY = codecopy,
                .PC = pc,
                .KECCAK256 = keccak256,
                .MSIZE = msize,
                .COINBASE = coinbase,
                .TIMESTAMP = timestamp,
                .NUMBER = number,
                .DIFFICULTY = difficulty,
                .GASLIMIT = gaslimit,
            });
            inline for (1..32) |n| {
                t[@intFromEnum(Opcode.PUSH0) + n] = pushN(n);
            }
            inline for (1..16) |n| {
                t[@intFromEnum(Opcode.DUP1) + n - 1] = dupN(n);
            }
            inline for (1..16) |n| {
                t[@intFromEnum(Opcode.SWAP1) + n - 1] = swapN(n);
            }

            return t;
        }
    };
}
