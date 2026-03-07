const std = @import("std");
const evm = @import("evm.zig");
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
    i32,
    u16,
    *evm.Frame,
) evm.Errors!void;

// Returns implementations of opcodes for a given spec
pub fn Ops(comptime spec: Spec) type {
    return struct {
        // Tail calls the next instruction after checking to see if the execution has run out of gas
        // Increments the PC as well
        pub inline fn next(next_ip: InstructionPointer, gas: i32, stack_head: u16, frame: *evm.Frame) evm.Errors!void {
            if (gas < 0) {
                @branchHint(.unlikely);
                return evm.Errors.OutOfGas;
            }
            // It is safe to unwrap unconditionally here, jumpdest analysis should protect against a
            // null function pointer here.
            const next_op: Fn = @ptrCast(next_ip[0].?);
            return @call(.always_tail, next_op, .{ next_ip + 1, gas, stack_head, frame });
        }

        pub fn invalid(_: InstructionPointer, _: i32, _: u16, _: *evm.Frame) evm.Errors!void {
            return evm.Errors.InvalidOpcode;
        }

        pub fn stop(_: InstructionPointer, gas: i32, _: u16, frame: *evm.Frame) evm.Errors!void {
            // I would rather just return this instead of writing it to the frame
            // but https://github.com/ziglang/zig/issues/18189
            frame.gas = gas;
            return;
        }

        pub fn pop(next_ip: InstructionPointer, gas: i32, stack_head: u16, frame: *evm.Frame) evm.Errors!void {
            const new_stack_head, _ = try frame.stackPop(stack_head, 1, 0);
            return next(next_ip, gas - spec.constantGas(.POP), new_stack_head, frame);
        }

        pub fn add(next_ip: InstructionPointer, gas: i32, stack_head: u16, frame: *evm.Frame) evm.Errors!void {
            const new_stack_head, const args = try frame.stackPop(stack_head, 2, 1);
            args[0] = args[1] +% args[0];
            return next(next_ip, gas - spec.constantGas(.ADD), new_stack_head, frame);
        }

        pub fn mul(next_ip: InstructionPointer, gas: i32, stack_head: u16, frame: *evm.Frame) evm.Errors!void {
            const new_stack_head, const args = try frame.stackPop(stack_head, 2, 1);
            args[0] = args[1] *% args[0];
            return next(next_ip, gas - spec.constantGas(.MUL), new_stack_head, frame);
        }

        pub fn sub(next_ip: InstructionPointer, gas: i32, stack_head: u16, frame: *evm.Frame) evm.Errors!void {
            const new_stack_head, const args = try frame.stackPop(stack_head, 2, 1);
            args[0] = args[1] -% args[0];
            return next(next_ip, gas - spec.constantGas(.SUB), new_stack_head, frame);
        }

        pub fn div(next_ip: InstructionPointer, gas: i32, stack_head: u16, frame: *evm.Frame) evm.Errors!void {
            const new_stack_head, const args = try frame.stackPop(stack_head, 2, 1);
            args[0] = if (args[0] == 0) 0 else args[1] / args[0];
            return next(next_ip, gas - spec.constantGas(.DIV), new_stack_head, frame);
        }

        pub fn sdiv(next_ip: InstructionPointer, gas: i32, stack_head: u16, frame: *evm.Frame) evm.Errors!void {
            const new_stack_head, const args = try frame.stackPop(stack_head, 2, 1);
            args[0] = @bitCast(@divTrunc(@as(i256, @bitCast(args[1])), @as(i256, @bitCast(args[0]))));
            return next(next_ip, gas - spec.constantGas(.SDIV), new_stack_head, frame);
        }

        pub fn mod(next_ip: InstructionPointer, gas: i32, stack_head: u16, frame: *evm.Frame) evm.Errors!void {
            const new_stack_head, const args = try frame.stackPop(stack_head, 2, 1);
            args[0] = if (args[0] == 0) 0 else @mod(args[1], args[0]);
            return next(next_ip, gas - spec.constantGas(.MOD), new_stack_head, frame);
        }

        pub fn smod(next_ip: InstructionPointer, gas: i32, stack_head: u16, frame: *evm.Frame) evm.Errors!void {
            const new_stack_head, const args = try frame.stackPop(stack_head, 2, 1);
            args[0] = if (args[0] == 0) 0 else @bitCast(@mod(@as(i256, @bitCast(args[1])), @as(i256, @bitCast(args[0]))));
            return next(next_ip, gas - spec.constantGas(.SMOD), new_stack_head, frame);
        }

        pub fn addmod(next_ip: InstructionPointer, gas: i32, stack_head: u16, frame: *evm.Frame) evm.Errors!void {
            const new_stack_head, const args = try frame.stackPop(stack_head, 3, 1);
            args[0] = if (args[0] == 0) 0 else @intCast(@mod(@as(u257, args[2]) + @as(u257, args[1]), args[0]));
            return next(next_ip, gas - spec.constantGas(.ADDMOD), new_stack_head, frame);
        }

        pub fn mulmod(next_ip: InstructionPointer, gas: i32, stack_head: u16, frame: *evm.Frame) evm.Errors!void {
            const new_stack_head, const args = try frame.stackPop(stack_head, 3, 1);
            args[0] = if (args[0] == 0) 0 else @intCast(@mod(@as(u512, args[2]) * @as(u512, args[1]), args[0]));
            return next(next_ip, gas - spec.constantGas(.MULMOD), new_stack_head, frame);
        }

        pub fn exp(next_ip: InstructionPointer, gas: i32, stack_head: u16, frame: *evm.Frame) evm.Errors!void {
            const new_stack_head, const args = try frame.stackPop(stack_head, 2, 1);
            args[0] = std.math.pow(u256, args[1], args[0]);
            return next(next_ip, gas - spec.constantGas(.EXP), new_stack_head, frame);
        }

        pub fn signextend(next_ip: InstructionPointer, gas: i32, stack_head: u16, frame: *evm.Frame) evm.Errors!void {
            const new_stack_head, const args = try frame.stackPop(stack_head, 2, 1);
            if (args[1] <= 30) {
                const size: u5 = @intCast(args[1]);
                switch (size) {
                    inline 0...30 => |bytes| {
                        const bit_size = (@as(u16, bytes) + 1) * 8;
                        const truncated: std.meta.Int(.unsigned, bit_size) = @truncate(args[0]);
                        const truncated_signed: std.meta.Int(.signed, bit_size) = @bitCast(truncated);
                        const extended_signed: i256 = @intCast(truncated_signed);
                        args[0] = @bitCast(extended_signed);
                    },
                    else => unreachable,
                }
            }
            return next(next_ip, gas - spec.constantGas(.SIGNEXTEND), new_stack_head, frame);
        }

        pub fn lt(next_ip: InstructionPointer, gas: i32, stack_head: u16, frame: *evm.Frame) evm.Errors!void {
            const new_stack_head, const args = try frame.stackPop(stack_head, 2, 1);
            args[0] = @intFromBool(args[1] < args[0]);
            return next(next_ip, gas - spec.constantGas(.LT), new_stack_head, frame);
        }

        pub fn gt(next_ip: InstructionPointer, gas: i32, stack_head: u16, frame: *evm.Frame) evm.Errors!void {
            const new_stack_head, const args = try frame.stackPop(stack_head, 2, 1);
            args[0] = @intFromBool(args[1] > args[0]);
            return next(next_ip, gas - spec.constantGas(.GT), new_stack_head, frame);
        }

        pub fn slt(next_ip: InstructionPointer, gas: i32, stack_head: u16, frame: *evm.Frame) evm.Errors!void {
            const new_stack_head, const args = try frame.stackPop(stack_head, 2, 1);
            args[0] = @intFromBool(@as(i256, @bitCast(args[1])) < @as(i256, @bitCast(args[0])));
            return next(next_ip, gas - spec.constantGas(.SLT), new_stack_head, frame);
        }

        pub fn sgt(next_ip: InstructionPointer, gas: i32, stack_head: u16, frame: *evm.Frame) evm.Errors!void {
            const new_stack_head, const args = try frame.stackPop(stack_head, 2, 1);
            args[0] = @intFromBool(@as(i256, @bitCast(args[1])) > @as(i256, @bitCast(args[0])));
            return next(next_ip, gas - spec.constantGas(.SGT), new_stack_head, frame);
        }

        pub fn eq(next_ip: InstructionPointer, gas: i32, stack_head: u16, frame: *evm.Frame) evm.Errors!void {
            const new_stack_head, const args = try frame.stackPop(stack_head, 2, 1);
            args[0] = @intFromBool(args[1] == args[0]);
            return next(next_ip, gas - spec.constantGas(.EQ), new_stack_head, frame);
        }

        pub fn iszero(next_ip: InstructionPointer, gas: i32, stack_head: u16, frame: *evm.Frame) evm.Errors!void {
            const new_stack_head, const args = try frame.stackPop(stack_head, 1, 1);
            args[0] = @intFromBool(args[0] == 0);
            return next(next_ip, gas - spec.constantGas(.ISZERO), new_stack_head, frame);
        }

        pub fn @"and"(next_ip: InstructionPointer, gas: i32, stack_head: u16, frame: *evm.Frame) evm.Errors!void {
            const new_stack_head, const args = try frame.stackPop(stack_head, 2, 1);
            args[0] = args[1] & args[0];
            return next(next_ip, gas - spec.constantGas(.AND), new_stack_head, frame);
        }

        pub fn @"or"(next_ip: InstructionPointer, gas: i32, stack_head: u16, frame: *evm.Frame) evm.Errors!void {
            const new_stack_head, const args = try frame.stackPop(stack_head, 2, 1);
            args[0] = args[1] | args[0];
            return next(next_ip, gas - spec.constantGas(.OR), new_stack_head, frame);
        }

        pub fn xor(next_ip: InstructionPointer, gas: i32, stack_head: u16, frame: *evm.Frame) evm.Errors!void {
            const new_stack_head, const args = try frame.stackPop(stack_head, 2, 1);
            args[0] = args[1] ^ args[0];
            return next(next_ip, gas - spec.constantGas(.XOR), new_stack_head, frame);
        }

        pub fn not(next_ip: InstructionPointer, gas: i32, stack_head: u16, frame: *evm.Frame) evm.Errors!void {
            const new_stack_head, const args = try frame.stackPop(stack_head, 1, 1);
            args[0] = ~args[0];
            return next(next_ip, gas - spec.constantGas(.NOT), new_stack_head, frame);
        }

        pub fn byte(next_ip: InstructionPointer, gas: i32, stack_head: u16, frame: *evm.Frame) evm.Errors!void {
            const new_stack_head, const args = try frame.stackPop(stack_head, 2, 1);
            if (args[1] > 31) {
                args[0] = 0;
            } else {
                const index: u5 = @intCast(args[1]);
                args[0] = @as(u8, @intCast(args[0] >> (index * 8)));
            }
            return next(next_ip, gas - spec.constantGas(.BYTE), new_stack_head, frame);
        }

        pub fn shl(next_ip: InstructionPointer, gas: i32, stack_head: u16, frame: *evm.Frame) evm.Errors!void {
            const new_stack_head, const args = try frame.stackPop(stack_head, 2, 1);
            if (args[1] >= 256) {
                args[0] = 0;
            } else {
                args[0] = args[0] << @intCast(args[1]);
            }
            return next(next_ip, gas - spec.constantGas(.SHL), new_stack_head, frame);
        }

        pub fn shr(next_ip: InstructionPointer, gas: i32, stack_head: u16, frame: *evm.Frame) evm.Errors!void {
            const new_stack_head, const args = try frame.stackPop(stack_head, 2, 1);
            if (args[1] >= 256) {
                args[0] = 0;
            } else {
                args[0] = args[0] >> @intCast(args[1]);
            }
            return next(next_ip, gas - spec.constantGas(.SHR), new_stack_head, frame);
        }

        pub fn sar(next_ip: InstructionPointer, gas: i32, stack_head: u16, frame: *evm.Frame) evm.Errors!void {
            const new_stack_head, const args = try frame.stackPop(stack_head, 2, 1);
            if (args[1] >= 256) {
                args[0] = 0;
            } else {
                args[0] = @bitCast(@as(i256, @bitCast(args[0])) >> @intCast(args[1]));
            }
            return next(next_ip, gas - spec.constantGas(.SAR), new_stack_head, frame);
        }

        pub fn jumpdest(next_ip: InstructionPointer, gas: i32, stack_head: u16, frame: *evm.Frame) evm.Errors!void {
            return next(next_ip, gas - spec.constantGas(.JUMPDEST), stack_head, frame);
        }

        pub fn jump(_: InstructionPointer, gas: i32, stack_head: u16, frame: *evm.Frame) evm.Errors!void {
            const new_stack_head, const args = try frame.stackPop(stack_head, 1, 0);
            const dest = frame.bytecode.isValidJumpDest(args[0]) orelse return evm.Errors.InvalidJumpDest;
            return next(dest, gas - spec.constantGas(.JUMP), new_stack_head, frame);
        }

        pub fn jumpi(next_ip: InstructionPointer, gas: i32, stack_head: u16, frame: *evm.Frame) evm.Errors!void {
            const new_stack_head, const args = try frame.stackPop(stack_head, 2, 0);
            if (args[0] == 0) {
                return next(next_ip, gas - spec.constantGas(.JUMPI), new_stack_head, frame);
            }

            const dest = frame.bytecode.isValidJumpDest(args[1]) orelse return evm.Errors.InvalidJumpDest;
            return next(dest, gas - spec.constantGas(.JUMPI), new_stack_head, frame);
        }

        pub fn opGas(next_ip: InstructionPointer, gas: i32, stack_head: u16, frame: *evm.Frame) evm.Errors!void {
            const new_stack_head = try frame.stackPush(stack_head, @intCast(gas));
            return next(next_ip, gas - spec.constantGas(.GAS), new_stack_head, frame);
        }

        pub fn pushN(comptime n: usize) Fn {
            return struct {
                pub fn push(next_ip: InstructionPointer, gas: i32, stack_head: u16, frame: *evm.Frame) evm.Errors!void {
                    const new_stack_head, const slot = try frame.stackReserve(stack_head);
                    frame.bytecode.readBytesToValue(next_ip, n, slot);
                    return next(next_ip + n, gas - spec.constantGas(@enumFromInt(@intFromEnum(Opcode.PUSH0) + n)), new_stack_head, frame);
                }
            }.push;
        }

        pub fn dupN(comptime n: usize) Fn {
            return struct {
                pub fn dup(next_ip: InstructionPointer, gas: i32, stack_head: u16, frame: *evm.Frame) evm.Errors!void {
                    var new_stack_head, const s = try frame.stackPop(stack_head, n, n);
                    new_stack_head = try frame.stackPush(new_stack_head, s[0]);
                    return next(next_ip, gas - spec.constantGas(@enumFromInt(@intFromEnum(Opcode.DUP1) + n - 1)), new_stack_head, frame);
                }
            }.dup;
        }

        pub fn swapN(comptime n: usize) Fn {
            return struct {
                pub fn swap(next_ip: InstructionPointer, gas: i32, stack_head: u16, frame: *evm.Frame) evm.Errors!void {
                    const new_stack_head, const s = try frame.stackPop(stack_head, n + 1, n + 1);
                    const tmp = s[0];
                    s[0] = s[n];
                    s[n] = tmp;
                    return next(next_ip, gas - spec.constantGas(@enumFromInt(@intFromEnum(Opcode.SWAP1) + n - 1)), new_stack_head, frame);
                }
            }.swap;
        }

        pub fn callvalue(next_ip: InstructionPointer, gas: i32, stack_head: u16, frame: *evm.Frame) evm.Errors!void {
            const new_stack_head = try frame.stackPush(stack_head, frame.value);
            return next(next_ip, gas - spec.constantGas(.CALLVALUE), new_stack_head, frame);
        }

        pub fn calldataload(next_ip: InstructionPointer, gas: i32, stack_head: u16, frame: *evm.Frame) evm.Errors!void {
            const new_stack_head, const args = try frame.stackPop(stack_head, 1, 1);
            if (args[0] > frame.calldata.len) {
                args[0] = 0;
            } else {
                const index: usize = @intCast(args[0]);
                const end = @min(frame.calldata.len, index + 32);
                args[0] = std.mem.readVarInt(u256, frame.calldata[index..end], .big);
            }
            return next(next_ip, gas - spec.constantGas(.CALLDATALOAD), new_stack_head, frame);
        }

        pub fn calldatasize(next_ip: InstructionPointer, gas: i32, stack_head: u16, frame: *evm.Frame) evm.Errors!void {
            const new_stack_head = try frame.stackPush(stack_head, @intCast(frame.calldata.len));
            return next(next_ip, gas - spec.constantGas(.CALLDATASIZE), new_stack_head, frame);
        }

        pub fn calldatacopy(next_ip: InstructionPointer, gas: i32, stack_head: u16, frame: *evm.Frame) evm.Errors!void {
            const new_stack_head, const args = try frame.stackPop(stack_head, 3, 0);
            const available_gas = gas - try frame.memory.growToFit(args[2], args[0], gas);

            const calldata = frame.safeSliceCalldata(args[1], @intCast(args[0]));
            frame.memory.copyAndClearRemaining(@intCast(args[2]), @intCast(args[0]), calldata);
            return next(next_ip, available_gas - spec.constantGas(.CALLDATACOPY), new_stack_head, frame);
        }

        pub fn codesize(next_ip: InstructionPointer, gas: i32, stack_head: u16, frame: *evm.Frame) evm.Errors!void {
            const new_stack_head = try frame.stackPush(stack_head, frame.bytecode.bytecode.len);
            return next(next_ip, gas - spec.constantGas(.CODESIZE), new_stack_head, frame);
        }

        pub fn codecopy(next_ip: InstructionPointer, gas: i32, stack_head: u16, frame: *evm.Frame) evm.Errors!void {
            const new_stack_head, const args = try frame.stackPop(stack_head, 3, 0);
            const available_gas = gas - try frame.memory.growToFit(args[2], args[0], gas);

            const bytecode = frame.bytecode.safeSlice(args[1], @intCast(args[0]));
            frame.memory.copyAndClearRemaining(@intCast(args[2]), @intCast(args[0]), bytecode);
            return next(next_ip, available_gas - spec.constantGas(.CODECOPY), new_stack_head, frame);
        }

        pub fn pc(next_ip: InstructionPointer, gas: i32, stack_head: u16, frame: *evm.Frame) evm.Errors!void {
            const new_stack_head = try frame.stackPush(stack_head, frame.bytecode.programCounter(next_ip) - 1);
            return next(next_ip, gas - spec.constantGas(.PC), new_stack_head, frame);
        }

        pub fn keccak256(next_ip: InstructionPointer, gas: i32, stack_head: u16, frame: *evm.Frame) evm.Errors!void {
            const new_stack_head, const args = try frame.stackPop(stack_head, 2, 1);
            const available_gas = gas - try frame.memory.growToFit(args[1], args[0], gas);

            const data = frame.memory.slice(@intCast(args[1]), @intCast(args[0]));
            std.crypto.hash.sha3.Keccak256.hash(data, @ptrCast(&args[0]), .{});
            return next(next_ip, available_gas - spec.constantGas(.KECCAK256), new_stack_head, frame);
        }

        pub fn msize(next_ip: InstructionPointer, gas: i32, stack_head: u16, frame: *evm.Frame) evm.Errors!void {
            const new_stack_head = try frame.stackPush(stack_head, frame.memory.buf.len);
            return next(next_ip, gas - spec.constantGas(.MSIZE), new_stack_head, frame);
        }

        pub fn coinbase(next_ip: InstructionPointer, gas: i32, stack_head: u16, frame: *evm.Frame) evm.Errors!void {
            const new_stack_head = try frame.stackPush(stack_head, frame.context.coinbase);
            return next(next_ip, gas - spec.constantGas(.COINBASE), new_stack_head, frame);
        }

        pub fn timestamp(next_ip: InstructionPointer, gas: i32, stack_head: u16, frame: *evm.Frame) evm.Errors!void {
            const new_stack_head = try frame.stackPush(stack_head, frame.context.time);
            return next(next_ip, gas - spec.constantGas(.TIMESTAMP), new_stack_head, frame);
        }

        pub fn number(next_ip: InstructionPointer, gas: i32, stack_head: u16, frame: *evm.Frame) evm.Errors!void {
            const new_stack_head = try frame.stackPush(stack_head, frame.context.number);
            return next(next_ip, gas - spec.constantGas(.NUMBER), new_stack_head, frame);
        }

        pub fn random(next_ip: InstructionPointer, gas: i32, stack_head: u16, frame: *evm.Frame) evm.Errors!void {
            const new_stack_head = try frame.stackPush(stack_head, frame.context.random);
            return next(next_ip, gas - spec.constantGas(.PREVRANDO), new_stack_head, frame);
        }

        pub fn gaslimit(next_ip: InstructionPointer, gas: i32, stack_head: u16, frame: *evm.Frame) evm.Errors!void {
            const new_stack_head = try frame.stackPush(stack_head, frame.context.gas_limit);
            return next(next_ip, gas - spec.constantGas(.GASLIMIT), new_stack_head, frame);
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
                .SHL = shl,
                .SHR = shr,
                .SAR = sar,
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
                .PREVRANDO = random,
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
