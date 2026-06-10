const std = @import("std");
const evm = @import("evm.zig");
const mem = @import("memory.zig");
const state = @import("state.zig");
const types = @import("../types.zig");
const storage = @import("storage.zig");
const uint256 = @import("uint256.zig");
const Opcode = @import("opcode.zig").Opcode;
const Bytecode = @import("bytecode.zig").Bytecode;
const Config = @import("config.zig").Config;
const Spec = @import("spec.zig").Spec;

// Type erased pointer to an opcode handler
// Used to circumvent shortcomings of Zig type system
pub const FnOpaquePtr = *align(@alignOf(usize)) const anyopaque;
const InstructionPointer = Bytecode.InstructionPointer;

// The interface that opcode handlers are required to implement
pub const Fn = *const fn (
    InstructionPointer,
    u32,
    u16,
    *evm.Frame,
) evm.Errors!void;

// Returns implementations of opcodes for a given spec
pub fn Ops(comptime cfg: Config) type {
    const fork = cfg.fork;
    return struct {
        // Tail calls the next instruction after checking to see if the execution has run out of gas
        // Increments the PC as well
        pub inline fn next(next_ip: InstructionPointer, gas: u32, cost: u32, stack_head: u16, frame: *evm.Frame) evm.Errors!void {
            if (gas < cost) {
                @branchHint(.unlikely);
                return evm.Errors.OutOfGas;
            }
            if (cfg.tracing_enabled) {
                tracing_hook(next_ip, gas - cost, stack_head, frame);
            }

            // It is safe to unwrap unconditionally here, jumpdest analysis should protect against a
            // null function pointer here.
            const next_op: Fn = @ptrCast(next_ip[0].?);
            return @call(.always_tail, next_op, .{ next_ip + 1, gas - cost, stack_head, frame });
        }

        pub fn invalid(_: InstructionPointer, _: u32, _: u16, _: *evm.Frame) evm.Errors!void {
            return evm.Errors.InvalidOpcode;
        }

        pub fn stop(_: InstructionPointer, gas: u32, _: u16, frame: *evm.Frame) evm.Errors!void {
            // I would rather just return this instead of writing it to the frame
            // but https://github.com/ziglang/zig/issues/18189
            frame.gas = @intCast(gas);
            frame.evm.return_data_size = 0;
        }

        pub fn pop(next_ip: InstructionPointer, gas: u32, stack_head: u16, frame: *evm.Frame) evm.Errors!void {
            const new_stack_head, _ = try frame.stackPop(stack_head, 1, 0);
            return next(next_ip, gas, fork.constantGas(.POP), new_stack_head, frame);
        }

        pub fn add(next_ip: InstructionPointer, gas: u32, stack_head: u16, frame: *evm.Frame) evm.Errors!void {
            const new_stack_head, const args = try frame.stackPop(stack_head, 2, 1);
            args[0] = args[1] +% args[0];
            return next(next_ip, gas, fork.constantGas(.ADD), new_stack_head, frame);
        }

        pub fn mul(next_ip: InstructionPointer, gas: u32, stack_head: u16, frame: *evm.Frame) evm.Errors!void {
            const new_stack_head, const args = try frame.stackPop(stack_head, 2, 1);
            args[0] = args[1] *% args[0];
            return next(next_ip, gas, fork.constantGas(.MUL), new_stack_head, frame);
        }

        pub fn sub(next_ip: InstructionPointer, gas: u32, stack_head: u16, frame: *evm.Frame) evm.Errors!void {
            const new_stack_head, const args = try frame.stackPop(stack_head, 2, 1);
            args[0] = args[1] -% args[0];
            return next(next_ip, gas, fork.constantGas(.SUB), new_stack_head, frame);
        }

        pub fn div(next_ip: InstructionPointer, gas: u32, stack_head: u16, frame: *evm.Frame) evm.Errors!void {
            const new_stack_head, const args = try frame.stackPop(stack_head, 2, 1);
            args[0] = uint256.div(args[1], args[0]);
            return next(next_ip, gas, fork.constantGas(.DIV), new_stack_head, frame);
        }

        pub fn sdiv(next_ip: InstructionPointer, gas: u32, stack_head: u16, frame: *evm.Frame) evm.Errors!void {
            const new_stack_head, const args = try frame.stackPop(stack_head, 2, 1);
            if (args[0] == 0) {
                args[0] = 0;
            } else {
                const sign_a = 0 -% (args[1] >> 255);
                const sign_b = 0 -% (args[0] >> 255);
                const abs_a = (args[1] ^ sign_a) +% (sign_a & 1);
                const abs_b = (args[0] ^ sign_b) +% (sign_b & 1);
                const result_sign = sign_a ^ sign_b;
                args[0] = (uint256.div(abs_a, abs_b) ^ result_sign) +% (result_sign & 1);
            }
            return next(next_ip, gas, fork.constantGas(.SDIV), new_stack_head, frame);
        }

        pub fn mod(next_ip: InstructionPointer, gas: u32, stack_head: u16, frame: *evm.Frame) evm.Errors!void {
            const new_stack_head, const args = try frame.stackPop(stack_head, 2, 1);
            args[0] = uint256.rem(args[1], args[0]);
            return next(next_ip, gas, fork.constantGas(.MOD), new_stack_head, frame);
        }

        pub fn smod(next_ip: InstructionPointer, gas: u32, stack_head: u16, frame: *evm.Frame) evm.Errors!void {
            const new_stack_head, const args = try frame.stackPop(stack_head, 2, 1);
            if (args[0] == 0) {
                args[0] = 0;
            } else {
                const sign_a = 0 -% (args[1] >> 255);
                const sign_b = 0 -% (args[0] >> 255);
                const abs_a = (args[1] ^ sign_a) +% (sign_a & 1);
                const abs_b = (args[0] ^ sign_b) +% (sign_b & 1);
                const r = uint256.rem(abs_a, abs_b);
                args[0] = (r ^ sign_a) +% (sign_a & 1);
            }
            return next(next_ip, gas, fork.constantGas(.SMOD), new_stack_head, frame);
        }

        pub fn addmod(next_ip: InstructionPointer, gas: u32, stack_head: u16, frame: *evm.Frame) evm.Errors!void {
            const new_stack_head, const args = try frame.stackPop(stack_head, 3, 1);
            // u257 prevents overflow before the modulo
            args[0] = if (args[0] == 0) 0 else @intCast(@mod(@as(u257, args[2]) + @as(u257, args[1]), args[0]));
            return next(next_ip, gas, fork.constantGas(.ADDMOD), new_stack_head, frame);
        }

        pub fn mulmod(next_ip: InstructionPointer, gas: u32, stack_head: u16, frame: *evm.Frame) evm.Errors!void {
            const new_stack_head, const args = try frame.stackPop(stack_head, 3, 1);
            // u512 prevents overflow before the modulo (256*256 = 512 bits max)
            args[0] = if (args[0] == 0) 0 else @intCast(@mod(@as(u512, args[2]) * @as(u512, args[1]), args[0]));
            return next(next_ip, gas, fork.constantGas(.MULMOD), new_stack_head, frame);
        }

        pub fn exp(next_ip: InstructionPointer, gas: u32, stack_head: u16, frame: *evm.Frame) evm.Errors!void {
            const new_stack_head, const args = try frame.stackPop(stack_head, 2, 1);
            var exponent = args[0];
            const exp_bytes: u32 = if (exponent == 0) 0 else @divFloor(256 - @as(u32, @clz(exponent)) + 7, 8);
            const dynamic_gas = fork.exp_per_byte_gas * exp_bytes;

            var base: u256 = args[1];
            var result: u256 = 1;

            while (exponent > 0) : (exponent >>= 1) {
                if (@as(u1, @truncate(exponent)) == 1) {
                    result = @truncate(@as(u512, result) * @as(u512, base));
                }
                base = @truncate(@as(u512, base) * @as(u512, base));
            }
            args[0] = result;
            return next(next_ip, gas, fork.constantGas(.EXP) + dynamic_gas, new_stack_head, frame);
        }

        pub fn signextend(next_ip: InstructionPointer, gas: u32, stack_head: u16, frame: *evm.Frame) evm.Errors!void {
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
            return next(next_ip, gas, fork.constantGas(.SIGNEXTEND), new_stack_head, frame);
        }

        pub fn lt(next_ip: InstructionPointer, gas: u32, stack_head: u16, frame: *evm.Frame) evm.Errors!void {
            const new_stack_head, const args = try frame.stackPop(stack_head, 2, 1);
            args[0] = @intFromBool(args[1] < args[0]);
            return next(next_ip, gas, fork.constantGas(.LT), new_stack_head, frame);
        }

        pub fn gt(next_ip: InstructionPointer, gas: u32, stack_head: u16, frame: *evm.Frame) evm.Errors!void {
            const new_stack_head, const args = try frame.stackPop(stack_head, 2, 1);
            args[0] = @intFromBool(args[1] > args[0]);
            return next(next_ip, gas, fork.constantGas(.GT), new_stack_head, frame);
        }

        pub fn slt(next_ip: InstructionPointer, gas: u32, stack_head: u16, frame: *evm.Frame) evm.Errors!void {
            const new_stack_head, const args = try frame.stackPop(stack_head, 2, 1);
            args[0] = @intFromBool(@as(i256, @bitCast(args[1])) < @as(i256, @bitCast(args[0])));
            return next(next_ip, gas, fork.constantGas(.SLT), new_stack_head, frame);
        }

        pub fn sgt(next_ip: InstructionPointer, gas: u32, stack_head: u16, frame: *evm.Frame) evm.Errors!void {
            const new_stack_head, const args = try frame.stackPop(stack_head, 2, 1);
            args[0] = @intFromBool(@as(i256, @bitCast(args[1])) > @as(i256, @bitCast(args[0])));
            return next(next_ip, gas, fork.constantGas(.SGT), new_stack_head, frame);
        }

        pub fn eq(next_ip: InstructionPointer, gas: u32, stack_head: u16, frame: *evm.Frame) evm.Errors!void {
            const new_stack_head, const args = try frame.stackPop(stack_head, 2, 1);
            args[0] = @intFromBool(args[1] == args[0]);
            return next(next_ip, gas, fork.constantGas(.EQ), new_stack_head, frame);
        }

        pub fn iszero(next_ip: InstructionPointer, gas: u32, stack_head: u16, frame: *evm.Frame) evm.Errors!void {
            const new_stack_head, const args = try frame.stackPop(stack_head, 1, 1);
            args[0] = @intFromBool(args[0] == 0);
            return next(next_ip, gas, fork.constantGas(.ISZERO), new_stack_head, frame);
        }

        pub fn @"and"(next_ip: InstructionPointer, gas: u32, stack_head: u16, frame: *evm.Frame) evm.Errors!void {
            const new_stack_head, const args = try frame.stackPop(stack_head, 2, 1);
            args[0] = args[1] & args[0];
            return next(next_ip, gas, fork.constantGas(.AND), new_stack_head, frame);
        }

        pub fn @"or"(next_ip: InstructionPointer, gas: u32, stack_head: u16, frame: *evm.Frame) evm.Errors!void {
            const new_stack_head, const args = try frame.stackPop(stack_head, 2, 1);
            args[0] = args[1] | args[0];
            return next(next_ip, gas, fork.constantGas(.OR), new_stack_head, frame);
        }

        pub fn xor(next_ip: InstructionPointer, gas: u32, stack_head: u16, frame: *evm.Frame) evm.Errors!void {
            const new_stack_head, const args = try frame.stackPop(stack_head, 2, 1);
            args[0] = args[1] ^ args[0];
            return next(next_ip, gas, fork.constantGas(.XOR), new_stack_head, frame);
        }

        pub fn not(next_ip: InstructionPointer, gas: u32, stack_head: u16, frame: *evm.Frame) evm.Errors!void {
            const new_stack_head, const args = try frame.stackPop(stack_head, 1, 1);
            args[0] = ~args[0];
            return next(next_ip, gas, fork.constantGas(.NOT), new_stack_head, frame);
        }

        pub fn byte(next_ip: InstructionPointer, gas: u32, stack_head: u16, frame: *evm.Frame) evm.Errors!void {
            const new_stack_head, const args = try frame.stackPop(stack_head, 2, 1);
            if (args[1] > 31) {
                args[0] = 0;
            } else {
                // EVM is big-endian: byte 0 is the most significant byte (bits 255–248)
                const index = 31 - @as(u8, @intCast(args[1]));
                args[0] = @as(u8, @truncate(args[0] >> (index * 8)));
            }
            return next(next_ip, gas, fork.constantGas(.BYTE), new_stack_head, frame);
        }

        pub fn shl(next_ip: InstructionPointer, gas: u32, stack_head: u16, frame: *evm.Frame) evm.Errors!void {
            const new_stack_head, const args = try frame.stackPop(stack_head, 2, 1);
            if (args[1] >= 256) {
                args[0] = 0;
            } else {
                args[0] = args[0] << @intCast(args[1]);
            }
            return next(next_ip, gas, fork.constantGas(.SHL), new_stack_head, frame);
        }

        pub fn shr(next_ip: InstructionPointer, gas: u32, stack_head: u16, frame: *evm.Frame) evm.Errors!void {
            const new_stack_head, const args = try frame.stackPop(stack_head, 2, 1);
            if (args[1] >= 256) {
                args[0] = 0;
            } else {
                args[0] = args[0] >> @intCast(args[1]);
            }
            return next(next_ip, gas, fork.constantGas(.SHR), new_stack_head, frame);
        }

        pub fn sar(next_ip: InstructionPointer, gas: u32, stack_head: u16, frame: *evm.Frame) evm.Errors!void {
            const new_stack_head, const args = try frame.stackPop(stack_head, 2, 1);
            const value = @as(i256, @bitCast(args[0]));
            if (args[1] >= 256) {
                args[0] = if (value >= 0) 0 else std.math.maxInt(u256);
            } else {
                args[0] = @bitCast(value >> @intCast(args[1]));
            }
            return next(next_ip, gas, fork.constantGas(.SAR), new_stack_head, frame);
        }

        pub fn clz(next_ip: InstructionPointer, gas: u32, stack_head: u16, frame: *evm.Frame) evm.Errors!void {
            const new_stack_head, const args = try frame.stackPop(stack_head, 1, 1);
            args[0] = @clz(args[0]);
            return next(next_ip, gas, fork.constantGas(.CLZ), new_stack_head, frame);
        }

        pub fn jumpdest(next_ip: InstructionPointer, gas: u32, stack_head: u16, frame: *evm.Frame) evm.Errors!void {
            return next(next_ip, gas, fork.constantGas(.JUMPDEST), stack_head, frame);
        }

        pub fn jump(_: InstructionPointer, gas: u32, stack_head: u16, frame: *evm.Frame) evm.Errors!void {
            const new_stack_head, const args = try frame.stackPop(stack_head, 1, 0);
            const dest = frame.code.isValidJumpDest(args[0]) orelse return evm.Errors.InvalidJumpDest;
            return next(dest, gas, fork.constantGas(.JUMP), new_stack_head, frame);
        }

        pub fn jumpi(next_ip: InstructionPointer, gas: u32, stack_head: u16, frame: *evm.Frame) evm.Errors!void {
            const new_stack_head, const args = try frame.stackPop(stack_head, 2, 0);
            if (args[0] == 0) {
                return next(next_ip, gas, fork.constantGas(.JUMPI), new_stack_head, frame);
            }

            const dest = frame.code.isValidJumpDest(args[1]) orelse return evm.Errors.InvalidJumpDest;
            return next(dest, gas, fork.constantGas(.JUMPI), new_stack_head, frame);
        }

        pub fn opGas(next_ip: InstructionPointer, gas: u32, stack_head: u16, frame: *evm.Frame) evm.Errors!void {
            if (gas < fork.constantGas(.GAS)) {
                return evm.Errors.OutOfGas;
            }
            const remaining_gas = gas - fork.constantGas(.GAS);
            const new_stack_head = try frame.stackPush(stack_head, @intCast(remaining_gas));
            return next(next_ip, remaining_gas, 0, new_stack_head, frame);
        }

        pub fn pushN(comptime n: usize) Fn {
            return struct {
                pub fn push(next_ip: InstructionPointer, gas: u32, stack_head: u16, frame: *evm.Frame) evm.Errors!void {
                    const new_stack_head, const slot = try frame.stackReserve(stack_head);
                    frame.code.readBytesToValue(next_ip, n, slot);
                    return next(next_ip + n, gas, fork.constantGas(@enumFromInt(@intFromEnum(Opcode.PUSH0) + n)), new_stack_head, frame);
                }
            }.push;
        }

        pub fn dupN(comptime n: usize) Fn {
            return struct {
                pub fn dup(next_ip: InstructionPointer, gas: u32, stack_head: u16, frame: *evm.Frame) evm.Errors!void {
                    var new_stack_head, const s = try frame.stackPop(stack_head, n, n);
                    new_stack_head = try frame.stackPush(new_stack_head, s[0]);
                    return next(next_ip, gas, fork.constantGas(@enumFromInt(Opcode.DUP1.byte() + n - 1)), new_stack_head, frame);
                }
            }.dup;
        }

        pub fn swapN(comptime n: usize) Fn {
            return struct {
                pub fn swap(next_ip: InstructionPointer, gas: u32, stack_head: u16, frame: *evm.Frame) evm.Errors!void {
                    const new_stack_head, const s = try frame.stackPop(stack_head, n + 1, n + 1);
                    const tmp = s[0];
                    s[0] = s[n];
                    s[n] = tmp;
                    return next(next_ip, gas, fork.constantGas(@enumFromInt(Opcode.SWAP1.byte() + n - 1)), new_stack_head, frame);
                }
            }.swap;
        }

        fn decodeSingle(imm: u8) u16 {
            return @as(u16, imm +% 145);
        }

        fn decodePair(imm: u8) struct { u16, u16 } {
            const k: u8 = imm ^ 0x8F;
            const q: u16 = k / 16;
            const r: u16 = k % 16;
            return if (q < r) .{ q + 1, r + 1 } else .{ r + 1, 29 - q };
        }

        pub fn dupn(next_ip: InstructionPointer, gas: u32, stack_head: u16, frame: *evm.Frame) evm.Errors!void {
            const n = decodeSingle(frame.code.readByte(next_ip));
            if (stack_head < n) return evm.Errors.StackUnderflow;
            const new_stack_head, const slot = try frame.stackReserve(stack_head);
            slot.* = frame.stack[stack_head - n];
            return next(next_ip + 1, gas, fork.constantGas(.DUPN), new_stack_head, frame);
        }

        pub fn swapn(next_ip: InstructionPointer, gas: u32, stack_head: u16, frame: *evm.Frame) evm.Errors!void {
            const n = decodeSingle(frame.code.readByte(next_ip));
            if (stack_head <= n) return evm.Errors.StackUnderflow;
            const tmp = frame.stack[stack_head - 1];
            frame.stack[stack_head - 1] = frame.stack[stack_head - 1 - n];
            frame.stack[stack_head - 1 - n] = tmp;
            return next(next_ip + 1, gas, fork.constantGas(.SWAPN), stack_head, frame);
        }

        pub fn exchange(next_ip: InstructionPointer, gas: u32, stack_head: u16, frame: *evm.Frame) evm.Errors!void {
            const n, const m = decodePair(frame.code.readByte(next_ip));
            if (stack_head <= m) return evm.Errors.StackUnderflow;
            const tmp = frame.stack[stack_head - 1 - n];
            frame.stack[stack_head - 1 - n] = frame.stack[stack_head - 1 - m];
            frame.stack[stack_head - 1 - m] = tmp;
            return next(next_ip + 1, gas, fork.constantGas(.EXCHANGE), stack_head, frame);
        }

        pub fn address(next_ip: InstructionPointer, gas: u32, stack_head: u16, frame: *evm.Frame) evm.Errors!void {
            const new_stack_head = try frame.stackPush(stack_head, frame.target);
            return next(next_ip, gas, fork.constantGas(.ADDRESS), new_stack_head, frame);
        }

        pub fn selfbalance(next_ip: InstructionPointer, gas: u32, stack_head: u16, frame: *evm.Frame) evm.Errors!void {
            const acc = try frame.state.accounts.read(frame.target);
            const new_stack_head = try frame.stackPush(stack_head, acc.balance);
            return next(next_ip, gas, fork.constantGas(.SELFBALANCE), new_stack_head, frame);
        }

        pub fn balance(next_ip: InstructionPointer, gas: u32, stack_head: u16, frame: *evm.Frame) evm.Errors!void {
            const new_stack_head, const args = try frame.stackPop(stack_head, 1, 1);
            const target: u160 = @truncate(args[0]);
            const dynamic_cost = frame.evm.accessAccountCost(fork, target);
            if (gas < dynamic_cost) {
                return evm.Errors.OutOfGas;
            }

            args[0] = (try frame.state.accounts.read(target)).balance;
            return next(next_ip, gas, fork.constantGas(.BALANCE) + dynamic_cost, new_stack_head, frame);
        }

        pub fn origin(next_ip: InstructionPointer, gas: u32, stack_head: u16, frame: *evm.Frame) evm.Errors!void {
            const new_stack_head = try frame.stackPush(stack_head, frame.evm.msg.caller);
            return next(next_ip, gas, fork.constantGas(.ORIGIN), new_stack_head, frame);
        }

        pub fn caller(next_ip: InstructionPointer, gas: u32, stack_head: u16, frame: *evm.Frame) evm.Errors!void {
            const new_stack_head = try frame.stackPush(stack_head, frame.caller);
            return next(next_ip, gas, fork.constantGas(.CALLER), new_stack_head, frame);
        }

        pub fn callvalue(next_ip: InstructionPointer, gas: u32, stack_head: u16, frame: *evm.Frame) evm.Errors!void {
            const new_stack_head = try frame.stackPush(stack_head, frame.value);
            return next(next_ip, gas, fork.constantGas(.CALLVALUE), new_stack_head, frame);
        }

        pub fn calldataload(next_ip: InstructionPointer, gas: u32, stack_head: u16, frame: *evm.Frame) evm.Errors!void {
            const new_stack_head, const args = try frame.stackPop(stack_head, 1, 1);
            if (args[0] > frame.calldata.len) {
                args[0] = 0;
            } else {
                const index: usize = @intCast(args[0]);
                const end = @min(frame.calldata.len, index + 32);
                const bytes = frame.calldata[index..end];

                readBeSliceToU256(bytes, 32, &args[0]);
            }
            return next(next_ip, gas, fork.constantGas(.CALLDATALOAD), new_stack_head, frame);
        }

        pub fn calldatasize(next_ip: InstructionPointer, gas: u32, stack_head: u16, frame: *evm.Frame) evm.Errors!void {
            const new_stack_head = try frame.stackPush(stack_head, @intCast(frame.calldata.len));
            return next(next_ip, gas, fork.constantGas(.CALLDATASIZE), new_stack_head, frame);
        }

        pub fn calldatacopy(next_ip: InstructionPointer, gas: u32, stack_head: u16, frame: *evm.Frame) evm.Errors!void {
            const new_stack_head, const args = try frame.stackPop(stack_head, 3, 0);
            const available_gas = try frame.memory.growToFit(args[2], args[0], gas);
            const dynamic_gas = mem.toWordSize(args[0]) * 3;

            const calldata = frame.safeSliceCalldata(args[1], @intCast(args[0]));
            frame.memory.copyAndClearRemaining(@truncate(args[2]), @intCast(args[0]), calldata);
            return next(next_ip, available_gas, fork.constantGas(.CALLDATACOPY) + dynamic_gas, new_stack_head, frame);
        }

        pub fn codesize(next_ip: InstructionPointer, gas: u32, stack_head: u16, frame: *evm.Frame) evm.Errors!void {
            const new_stack_head = try frame.stackPush(stack_head, frame.code.bytes.len);
            return next(next_ip, gas, fork.constantGas(.CODESIZE), new_stack_head, frame);
        }

        pub fn codecopy(next_ip: InstructionPointer, gas: u32, stack_head: u16, frame: *evm.Frame) evm.Errors!void {
            const new_stack_head, const args = try frame.stackPop(stack_head, 3, 0);
            const available_gas = try frame.memory.growToFit(args[2], args[0], gas);
            const dynamic_gas = mem.toWordSize(args[0]) * 3;

            const bytecode = frame.code.safeSlice(args[1], @intCast(args[0]));
            frame.memory.copyAndClearRemaining(@truncate(args[2]), @intCast(args[0]), bytecode);
            return next(next_ip, available_gas, fork.constantGas(.CODECOPY) + dynamic_gas, new_stack_head, frame);
        }

        pub fn extcodehash(next_ip: InstructionPointer, gas: u32, stack_head: u16, frame: *evm.Frame) evm.Errors!void {
            const new_stack_head, const args = try frame.stackPop(stack_head, 1, 1);
            const target: u160 = @truncate(args[0]);
            const dynamic_cost = frame.evm.accessAccountCost(fork, target);
            if (gas < dynamic_cost) {
                return evm.Errors.OutOfGas;
            }

            const account = try frame.state.accounts.read(target);
            args[0] = if (account.isEmptyAccount()) 0 else std.mem.readInt(u256, &account.code_hash, .big);
            return next(next_ip, gas, fork.constantGas(.EXTCODEHASH) + dynamic_cost, new_stack_head, frame);
        }

        pub fn extcodesize(next_ip: InstructionPointer, gas: u32, stack_head: u16, frame: *evm.Frame) evm.Errors!void {
            const new_stack_head, const args = try frame.stackPop(stack_head, 1, 1);
            const target: u160 = @truncate(args[0]);
            const dynamic_cost = frame.evm.accessAccountCost(fork, target);
            if (gas < dynamic_cost) {
                return evm.Errors.OutOfGas;
            }

            const code_hash = (try frame.state.accounts.read(target)).code_hash;
            if (!std.mem.eql(u8, &code_hash, &types.empty_code_hash)) {
                args[0] = (try frame.state.get_code(code_hash, cfg)).bytes.len;
            } else {
                args[0] = 0;
            }
            return next(next_ip, gas, fork.constantGas(.EXTCODESIZE) + dynamic_cost, new_stack_head, frame);
        }

        pub fn extcodecopy(next_ip: InstructionPointer, gas: u32, stack_head: u16, frame: *evm.Frame) evm.Errors!void {
            const new_stack_head, const args = try frame.stackPop(stack_head, 4, 0);
            var available_gas = try frame.memory.growToFit(args[2], args[0], gas);
            const target: u160 = @truncate(args[3]);
            const access_cost = frame.evm.accessAccountCost(fork, target);
            const dynamic_gas = mem.toWordSize(args[0]) * 3 + access_cost;
            if (available_gas < dynamic_gas) {
                return evm.Errors.OutOfGas;
            }
            available_gas -= dynamic_gas;

            const code_hash = (try frame.state.accounts.read(target)).code_hash;
            var slice: []const u8 = &[_]u8{};
            if (!std.mem.eql(u8, &code_hash, &types.empty_code_hash)) {
                const bytecode = try frame.state.get_code(code_hash, cfg);
                slice = bytecode.safeSlice(args[1], @intCast(args[0]));
            }
            frame.memory.copyAndClearRemaining(@truncate(args[2]), @intCast(args[0]), slice);
            return next(next_ip, available_gas, fork.constantGas(.EXTCODECOPY), new_stack_head, frame);
        }

        pub fn gasprice(next_ip: InstructionPointer, gas: u32, stack_head: u16, frame: *evm.Frame) evm.Errors!void {
            const new_stack_head = try frame.stackPush(stack_head, frame.evm.effective_gas_price);
            return next(next_ip, gas, fork.constantGas(.GASPRICE), new_stack_head, frame);
        }

        pub fn pc(next_ip: InstructionPointer, gas: u32, stack_head: u16, frame: *evm.Frame) evm.Errors!void {
            const new_stack_head = try frame.stackPush(stack_head, frame.code.programCounter(next_ip) - 1);
            return next(next_ip, gas, fork.constantGas(.PC), new_stack_head, frame);
        }

        pub fn keccak256(next_ip: InstructionPointer, gas: u32, stack_head: u16, frame: *evm.Frame) evm.Errors!void {
            const new_stack_head, const args = try frame.stackPop(stack_head, 2, 1);
            const available_gas = try frame.memory.growToFit(args[1], args[0], gas);
            const dynamic_gas = mem.toWordSize(args[0]) * fork.keccak_word_gas;
            const data = frame.memory.slice(@truncate(args[1]), @intCast(args[0]));
            var hash: [32]u8 = undefined;
            std.crypto.hash.sha3.Keccak256.hash(data, &hash, .{});
            args[0] = std.mem.readInt(u256, &hash, .big);
            return next(next_ip, available_gas, fork.constantGas(.KECCAK256) + dynamic_gas, new_stack_head, frame);
        }

        pub fn msize(next_ip: InstructionPointer, gas: u32, stack_head: u16, frame: *evm.Frame) evm.Errors!void {
            const new_stack_head = try frame.stackPush(stack_head, frame.memory.buf.len);
            return next(next_ip, gas, fork.constantGas(.MSIZE), new_stack_head, frame);
        }

        pub fn blockhash(next_ip: InstructionPointer, gas: u32, stack_head: u16, frame: *evm.Frame) evm.Errors!void {
            const new_stack_head, const args = try frame.stackPop(stack_head, 1, 1);
            const requested = args[0];
            const current = frame.evm.context.number;
            if (requested > std.math.maxInt(u64) or requested >= current or current - requested > 256) {
                args[0] = 0;
            } else {
                args[0] = frame.evm.context.ancestors[@as(usize, @intCast(current - @as(u64, @truncate(requested)) - 1))];
                if (args[0] == 0) return evm.Errors.MissingAncestorHash;
            }
            return next(next_ip, gas, fork.constantGas(.BLOCKHASH), new_stack_head, frame);
        }

        pub fn coinbase(next_ip: InstructionPointer, gas: u32, stack_head: u16, frame: *evm.Frame) evm.Errors!void {
            const new_stack_head = try frame.stackPush(stack_head, frame.context.coinbase);
            return next(next_ip, gas, fork.constantGas(.COINBASE), new_stack_head, frame);
        }

        pub fn timestamp(next_ip: InstructionPointer, gas: u32, stack_head: u16, frame: *evm.Frame) evm.Errors!void {
            const new_stack_head = try frame.stackPush(stack_head, frame.context.time);
            return next(next_ip, gas, fork.constantGas(.TIMESTAMP), new_stack_head, frame);
        }

        pub fn number(next_ip: InstructionPointer, gas: u32, stack_head: u16, frame: *evm.Frame) evm.Errors!void {
            const new_stack_head = try frame.stackPush(stack_head, frame.context.number);
            return next(next_ip, gas, fork.constantGas(.NUMBER), new_stack_head, frame);
        }

        pub fn random(next_ip: InstructionPointer, gas: u32, stack_head: u16, frame: *evm.Frame) evm.Errors!void {
            const new_stack_head = try frame.stackPush(stack_head, frame.context.random);
            return next(next_ip, gas, fork.constantGas(.PREVRANDO), new_stack_head, frame);
        }

        pub fn gaslimit(next_ip: InstructionPointer, gas: u32, stack_head: u16, frame: *evm.Frame) evm.Errors!void {
            const new_stack_head = try frame.stackPush(stack_head, frame.context.gas_limit);
            return next(next_ip, gas, fork.constantGas(.GASLIMIT), new_stack_head, frame);
        }

        pub fn chainid(next_ip: InstructionPointer, gas: u32, stack_head: u16, frame: *evm.Frame) evm.Errors!void {
            const new_stack_head = try frame.stackPush(stack_head, frame.context.chainid);
            return next(next_ip, gas, fork.constantGas(.CHAINID), new_stack_head, frame);
        }

        pub fn basefee(next_ip: InstructionPointer, gas: u32, stack_head: u16, frame: *evm.Frame) evm.Errors!void {
            const new_stack_head = try frame.stackPush(stack_head, frame.context.basefee);
            return next(next_ip, gas, fork.constantGas(.BASEFEE), new_stack_head, frame);
        }

        pub fn blobhash(next_ip: InstructionPointer, gas: u32, stack_head: u16, frame: *evm.Frame) evm.Errors!void {
            const new_stack_head, const args = try frame.stackPop(stack_head, 1, 1);
            const hashes = frame.evm.msg.blob_versioned_hashes;
            args[0] = if (std.math.cast(usize, args[0])) |i|
                if (i < hashes.len) hashes[i] else 0
            else
                0;
            return next(next_ip, gas, fork.constantGas(.BLOBHASH), new_stack_head, frame);
        }

        pub fn blobbasefee(next_ip: InstructionPointer, gas: u32, stack_head: u16, frame: *evm.Frame) evm.Errors!void {
            const new_stack_head = try frame.stackPush(stack_head, frame.evm.context.blob_base_fee);
            return next(next_ip, gas, fork.constantGas(.BLOBBASEFEE), new_stack_head, frame);
        }

        pub fn mload(next_ip: InstructionPointer, gas: u32, stack_head: u16, frame: *evm.Frame) evm.Errors!void {
            const new_stack_head, const args = try frame.stackPop(stack_head, 1, 1);
            const available_gas = try frame.memory.growToFit(args[0], 32, gas);

            const bytes = frame.memory.slice(@intCast(args[0]), 32);
            args[0] = std.mem.readInt(u256, bytes[0..32], .big);
            return next(next_ip, available_gas, fork.constantGas(.MLOAD), new_stack_head, frame);
        }

        pub fn mstore(next_ip: InstructionPointer, gas: u32, stack_head: u16, frame: *evm.Frame) evm.Errors!void {
            const new_stack_head, const args = try frame.stackPop(stack_head, 2, 0);
            const available_gas = try frame.memory.growToFit(args[1], 32, gas);

            const bytes = frame.memory.slice(@intCast(args[1]), 32);
            std.mem.writeInt(u256, bytes[0..32], args[0], .big);
            return next(next_ip, available_gas, fork.constantGas(.MSTORE), new_stack_head, frame);
        }

        pub fn mstore8(next_ip: InstructionPointer, gas: u32, stack_head: u16, frame: *evm.Frame) evm.Errors!void {
            const new_stack_head, const args = try frame.stackPop(stack_head, 2, 0);
            const available_gas = try frame.memory.growToFit(args[1], 1, gas);

            const bytes = frame.memory.slice(@intCast(args[1]), 1);
            bytes[0] = @truncate(args[0]);
            return next(next_ip, available_gas, fork.constantGas(.MSTORE8), new_stack_head, frame);
        }

        pub fn sload(next_ip: InstructionPointer, gas: u32, stack_head: u16, frame: *evm.Frame) evm.Errors!void {
            const new_stack_head, const args = try frame.stackPop(stack_head, 1, 1);
            const dynamic_gas = frame.evm.accessSlotCost(fork, frame.target, args[0]);
            if (gas < dynamic_gas) {
                return evm.Errors.OutOfGas;
            }
            const remaining_gas = gas - dynamic_gas;

            args[0] = try frame.state.contract_state.read(.{ .address = frame.target, .slot = args[0] });
            return next(next_ip, remaining_gas, 0, new_stack_head, frame);
        }

        // EIP-2200/EIP-3529 refund delta for an SSTORE.
        fn refund_sstore(new_value: u256, current_value: u256, original_value: u256) struct { i32, u32 } {
            if (new_value == current_value) return .{ 0, 0 };

            var delta: i32 = 0;

            if (original_value != 0) {
                if (current_value == 0) {
                    // A prior write in this tx cleared the slot and earned a refund;
                    // we are now writing non-zero, so revoke that refund.
                    delta -= fork.sstore_clears_schedule;
                }
                if (new_value == 0) {
                    // We are clearing a slot that held a non-zero original value.
                    delta += fork.sstore_clears_schedule;
                }
            }

            var state_gas_refund: u32 = 0;
            // Restoring a slot to its original value earns back the gas that was
            // charged above the cheap SLOAD cost.
            if (new_value == original_value) {
                if (original_value == 0) {
                    delta += fork.sstore_set_gas - fork.warm_access_gas;
                    state_gas_refund = evm.STATE_BYTES_PER_STORAGE_SLOT * fork.cpsb;
                } else {
                    delta += fork.sstore_reset_gas - fork.warm_access_gas;
                }
            }

            return .{ delta, state_gas_refund };
        }

        // EIP-2200 net-metered SSTORE gas: charges based on the transition from
        // original (pre-tx) value → current value → new value.
        fn gas_sstore(value: u256, current_value: u256, original_value: u256, is_warm: bool) struct { u32, u32 } {
            // cold slot access surcharge (EIP-2929)
            const base_dynamic_gas: u32 = if (is_warm) 0 else fork.cold_sload_gas;
            const storage_state_gas: u32 = evm.STATE_BYTES_PER_STORAGE_SLOT * fork.cpsb;

            if (value == current_value) {
                return .{ base_dynamic_gas + fork.warm_access_gas, 0 };
            } else if (current_value == original_value) {
                if (original_value == 0) {
                    return .{ base_dynamic_gas + fork.sstore_set_gas, if (value != 0) storage_state_gas else 0 };
                } else {
                    return .{ base_dynamic_gas + fork.sstore_reset_gas, 0 };
                }
            } else {
                return .{ base_dynamic_gas + fork.warm_access_gas, 0 };
            }
        }

        pub fn sstore(next_ip: InstructionPointer, gas: u32, stack_head: u16, frame: *evm.Frame) evm.Errors!void {
            if (frame.is_static) return evm.Errors.WriteProtection;
            if (gas <= fork.call_stipend) return evm.Errors.OutOfGas;
            const new_stack_head, const args = try frame.stackPop(stack_head, 2, 0);
            const lookup: types.StorageLookup = .{ .address = frame.target, .slot = args[1] };
            const is_warm = frame.evm.accessSlot(frame.target, args[1]);
            const old_value, _ = try frame.state.contract_state.write(lookup, args[0]);
            // lazily record the pre-tx value on first write; subsequent writes don't update it
            const original_value_entry = frame.evm.pre_state.getOrPutAssumeCapacity(lookup);
            if (!original_value_entry.found_existing) {
                original_value_entry.value_ptr.* = old_value;
            }
            const original_value = original_value_entry.value_ptr.*;
            const dynamic_gas, const state_gas = gas_sstore(args[0], old_value, original_value, is_warm);
            const regular_refund, const state_gas_refund = refund_sstore(args[0], old_value, original_value);
            frame.evm.gas_refund += regular_refund;
            frame.creditStateGasRefund(state_gas_refund);

            const regular_cost = fork.constantGas(.SSTORE) + dynamic_gas;
            if (gas < regular_cost) {
                return evm.Errors.OutOfGas;
            }
            var remaining_regular_gas = gas - regular_cost;
            remaining_regular_gas = try frame.chargeStateGas(remaining_regular_gas, state_gas);
            return next(next_ip, remaining_regular_gas, 0, new_stack_head, frame);
        }

        pub fn tload(next_ip: InstructionPointer, gas: u32, stack_head: u16, frame: *evm.Frame) evm.Errors!void {
            const new_stack_head, const args = try frame.stackPop(stack_head, 1, 1);
            args[0] = try frame.state.transient_storage.read(.{ .address = frame.target, .slot = args[0] });
            return next(next_ip, gas, fork.constantGas(.TLOAD), new_stack_head, frame);
        }

        pub fn tstore(next_ip: InstructionPointer, gas: u32, stack_head: u16, frame: *evm.Frame) evm.Errors!void {
            if (frame.is_static) return evm.Errors.WriteProtection;
            const new_stack_head, const args = try frame.stackPop(stack_head, 2, 0);
            _ = try frame.state.transient_storage.write(.{ .address = frame.target, .slot = args[1] }, args[0]);
            return next(next_ip, gas, fork.constantGas(.TSTORE), new_stack_head, frame);
        }

        pub fn mcopy(next_ip: InstructionPointer, gas: u32, stack_head: u16, frame: *evm.Frame) evm.Errors!void {
            const new_stack_head, const args = try frame.stackPop(stack_head, 3, 0);
            const available_gas = try frame.memory.growToFit(@max(args[2], args[1]), args[0], gas);
            const dynamic_gas = mem.toWordSize(args[0]) * 3;
            if (args[0] > 0) {
                const dest = frame.memory.slice(@intCast(args[2]), @intCast(args[0]));
                const src = frame.memory.slice(@intCast(args[1]), @intCast(args[0]));
                @memmove(dest, src);
            }
            return next(next_ip, available_gas, fork.constantGas(.MCOPY) + dynamic_gas, new_stack_head, frame);
        }

        pub fn create_variant(comptime variant: Opcode) Fn {
            return struct {
                pub fn create(next_ip: InstructionPointer, gas: u32, stack_head: u16, frame: *evm.Frame) evm.Errors!void {
                    if (frame.is_static) return evm.Errors.WriteProtection;

                    // Stack layout (args[0]=bottom, args[n-1]=top):
                    //   CREATE  (3): size offset value
                    //   CREATE2 (4): size offset value salt
                    const n_args = if (variant == .CREATE) 3 else 4;
                    const new_stack_head, const args = try frame.stackPop(stack_head, n_args, 1);

                    const value = args[n_args - 1];
                    const offset = args[n_args - 2];
                    const size = args[n_args - 3];
                    const salt: ?u256 = if (variant == .CREATE2) args[0] else null;

                    // EIP-3860: reject oversized initcode
                    if (size > 2 * fork.max_code_size) return evm.Errors.OutOfGas;

                    var available_gas = try frame.memory.growToFit(offset, size, gas);

                    // Deduct base cost and EIP-3860 initcode word cost
                    const initcode_word_cost: u32 = @intCast(mem.toWordSize(size) * 2);
                    if (available_gas < fork.constantGas(variant) + initcode_word_cost) return evm.Errors.OutOfGas;
                    available_gas -= fork.constantGas(variant) + initcode_word_cost;

                    // CREATE2 hashes initcode: keccak_word_gas per word
                    if (variant == .CREATE2) {
                        const hash_cost: u32 = @intCast(mem.toWordSize(size) * fork.keccak_word_gas);
                        if (available_gas < hash_cost) return evm.Errors.OutOfGas;
                        available_gas -= hash_cost;
                    }

                    const create_state_gas = evm.STATE_BYTES_PER_NEW_ACCOUNT * fork.cpsb;
                    available_gas = try frame.chargeStateGas(available_gas, create_state_gas);

                    // EIP-150: forward at most (denom-1)/denom of remaining gas
                    const max_forwardable = available_gas - @divFloor(available_gas, fork.gas_forward_denom);
                    available_gas -= max_forwardable;

                    const initcode = frame.memory.slice(@truncate(offset), @intCast(size));
                    const leftover_gas, const child_state_gas_used, const new_addr = try frame.evm.create(
                        cfg,
                        frame.state,
                        frame.target,
                        initcode,
                        value,
                        max_forwardable,
                        frame.depth,
                        salt,
                    );
                    available_gas += leftover_gas;
                    frame.state_gas_used += child_state_gas_used;
                    frame.creditStateGasRefund(if (new_addr == 0) create_state_gas else 0);
                    args[0] = new_addr; // 0 on failure, address on success
                    return next(next_ip, available_gas, 0, new_stack_head, frame);
                }
            }.create;
        }

        pub fn call_variant(comptime variant: Opcode) Fn {
            return struct {
                pub fn call(next_ip: InstructionPointer, gas: u32, stack_head: u16, frame: *evm.Frame) evm.Errors!void {
                    // CALL and CALLCODE consume a value arg from the stack; DELEGATECALL and STATICCALL do not
                    const has_value_arg = variant == .CALL or variant == .CALLCODE;
                    const n_args = if (has_value_arg) 7 else 6;

                    // Stack layout (args[0]=bottom, args[n-1]=top):
                    //   CALL/CALLCODE (7):      retSize retOffset argsSize argsOffset value addr gas
                    //   DELEGATECALL/STATICCALL(6): retSize retOffset argsSize argsOffset addr  gas
                    const new_stack_head, const args = try frame.stackPop(stack_head, n_args, 1);

                    var available_gas = try frame.memory.growToFit(args[1], args[0], gas);
                    available_gas = try frame.memory.growToFit(args[3], args[2], available_gas);

                    const addr: u160 = if (has_value_arg) @truncate(args[5]) else @truncate(args[4]);
                    const call_gas = if (has_value_arg) args[6] else args[5];

                    const address_access_cost = frame.evm.accessAccountCost(fork, addr);

                    const call_caller: u160 = if (variant == .DELEGATECALL) frame.caller else frame.target;
                    const call_target: u160 = switch (variant) {
                        .CALL, .STATICCALL => addr,
                        .CALLCODE, .DELEGATECALL => frame.target,
                        else => unreachable,
                    };
                    const value: u256 = switch (variant) {
                        .CALL, .CALLCODE => args[4],
                        .DELEGATECALL => frame.value,
                        .STATICCALL => 0,
                        else => unreachable,
                    };

                    const value_is_positive = value > 0;
                    // Only CALL is forbidden to transfer value in static context; CALLCODE/DELEGATECALL do not actually move ETH
                    if (frame.is_static and value_is_positive and variant == .CALL) return evm.Errors.WriteProtection;

                    const positive_value_cost = if ((variant == .CALL or variant == .CALLCODE) and value_is_positive)
                        fork.call_value_gas
                    else
                        0;
                    if (available_gas < address_access_cost + positive_value_cost) {
                        return evm.Errors.OutOfGas;
                    }

                    const stipend = if (positive_value_cost > 0) fork.call_stipend else 0;
                    const target_account = try frame.state.accounts.read(call_target);
                    const positive_value_to_new_acc_cost = if (variant == .CALL and value_is_positive and target_account.isEmptyAccount())
                        fork.call_new_account_gas
                    else
                        0;
                    // EIP-7702: if addr has a delegation designator, charge EIP-2929 access cost
                    // for following it. Charged here (from caller's gas), not from forwarded gas.
                    const delegation_cost = try frame.evm.delegationAccessCost(cfg, addr, frame.state);
                    const dynamic_cost = address_access_cost + delegation_cost + positive_value_cost + positive_value_to_new_acc_cost;
                    if (available_gas < dynamic_cost) {
                        return evm.Errors.OutOfGas;
                    }
                    available_gas -= dynamic_cost;

                    if (fork.isEnabled(.Amsterdam) and variant == .CALL and value_is_positive and target_account.isEmptyAccount()) {
                        available_gas = try frame.chargeStateGas(available_gas, evm.STATE_BYTES_PER_NEW_ACCOUNT * fork.cpsb);
                    }

                    // EIP-150: forward at most (denom-1)/denom of remaining gas to sub-calls
                    const forwarded_gas = @min(call_gas, available_gas - @divFloor(available_gas, fork.gas_forward_denom));
                    available_gas -= forwarded_gas;

                    const calldata = frame.memory.slice(@truncate(args[3]), @intCast(args[2]));
                    const return_buffer = frame.memory.slice(@truncate(args[1]), @intCast(args[0]));

                    const leftover_gas, const child_state_gas_used, const err = try frame.evm.call(
                        cfg,
                        frame.state,
                        call_caller,
                        call_target,
                        addr,
                        forwarded_gas + stipend,
                        calldata,
                        value,
                        frame.depth,
                        return_buffer,
                        comptime (variant == .DELEGATECALL),
                        frame.is_static or (variant == .STATICCALL),
                    );

                    args[0] = if (err != null) 0 else 1;
                    available_gas += leftover_gas;
                    frame.state_gas_used += child_state_gas_used;
                    return next(next_ip, available_gas, 0, new_stack_head, frame);
                }
            }.call;
        }

        pub fn return_variant(comptime variant: Opcode) Fn {
            return struct {
                pub fn @"return"(_: InstructionPointer, gas: u32, stack_head: u16, frame: *evm.Frame) evm.Errors!void {
                    _, const args = try frame.stackPop(stack_head, 2, 0);
                    const available_gas = try frame.memory.growToFit(args[1], args[0], gas);
                    const remaining = available_gas - fork.constantGas(variant);
                    if (remaining < 0) return evm.Errors.OutOfGas;

                    if (args[0] > 0) {
                        const source = frame.memory.slice(@intCast(args[1]), @intCast(args[0]));
                        const min_len = @min(frame.return_buffer.len, source.len);

                        @memcpy(frame.return_buffer[0..min_len], source[0..min_len]);
                        if (source.len > frame.evm.return_buffer.len) unreachable;
                        @memcpy(frame.evm.return_buffer[0..source.len], source);
                    }
                    frame.evm.return_data_size = @intCast(args[0]);
                    frame.gas = @intCast(remaining);

                    if (variant == .REVERT) {
                        return evm.Errors.Reverted;
                    }
                }
            }.@"return";
        }

        pub fn returndatasize(next_ip: InstructionPointer, gas: u32, stack_head: u16, frame: *evm.Frame) evm.Errors!void {
            const new_stack_head = try frame.stackPush(stack_head, frame.evm.return_data_size);
            return next(next_ip, gas, fork.constantGas(.RETURNDATASIZE), new_stack_head, frame);
        }

        pub fn returndatacopy(next_ip: InstructionPointer, gas: u32, stack_head: u16, frame: *evm.Frame) evm.Errors!void {
            const new_stack_head, const args = try frame.stackPop(stack_head, 3, 0);
            const available_gas = try frame.memory.growToFit(args[2], args[0], gas);
            const dynamic_gas = mem.toWordSize(args[0]) * 3;

            const end = std.math.add(u256, args[1], args[0]) catch return evm.Errors.ReturnDataOutOfBounds;
            if (end > frame.evm.return_data_size) {
                return evm.Errors.ReturnDataOutOfBounds;
            }

            const dest = frame.memory.slice(@truncate(args[2]), @intCast(args[0]));
            @memcpy(dest, frame.evm.return_buffer[@intCast(args[1])..@intCast(end)]);

            return next(next_ip, available_gas, fork.constantGas(.RETURNDATACOPY) + dynamic_gas, new_stack_head, frame);
        }

        pub fn selfdestruct(_: InstructionPointer, gas: u32, stack_head: u16, frame: *evm.Frame) evm.Errors!void {
            if (frame.is_static) return evm.Errors.WriteProtection;

            _, const args = try frame.stackPop(stack_head, 1, 0);
            const beneficiary: u160 = @truncate(args[0]);

            const is_warm = frame.evm.accessAccount(beneficiary);
            const access_cost = if (!is_warm) fork.cold_account_access_gas else 0;

            const cost = access_cost + fork.constantGas(.SELFDESTRUCT);
            if (gas < cost) {
                return evm.Errors.OutOfGas;
            }
            var remaining = gas - cost;

            var target_was_empty = false;
            var empty_account_cost: u32 = 0;
            const transferred_value = (try frame.state.accounts.read(frame.target)).balance;
            const is_new_account = frame.evm.markForDestruction(frame.target);
            if (transferred_value > 0 and (is_new_account or beneficiary != frame.target)) {
                var beneficiary_account = try frame.state.accounts.update(beneficiary);
                target_was_empty = beneficiary_account.isEmptyAccount();
                if (target_was_empty) {
                    empty_account_cost = fork.selfdestruct_empty_target_gas;
                }
                beneficiary_account.balance += transferred_value;
                (try frame.state.accounts.update(frame.target)).balance = 0;
                if (fork.isEnabled(.Amsterdam)) {
                    if (beneficiary != frame.target) {
                        frame.evm.pushTransferLog(frame.target, beneficiary, transferred_value);
                    } else {
                        frame.evm.pushBurnLog(frame.target, transferred_value);
                    }
                }
            } else {
                _ = try frame.state.accounts.read(beneficiary); // BAL requires us to do that
            }

            if (remaining < empty_account_cost) {
                return evm.Errors.OutOfGas;
            }
            remaining -= empty_account_cost;

            if (fork.isEnabled(.Amsterdam) and target_was_empty) {
                frame.gas = try frame.chargeStateGas(@intCast(remaining), evm.STATE_BYTES_PER_NEW_ACCOUNT * fork.cpsb);
            } else {
                frame.gas = @intCast(remaining);
            }
        }

        pub fn log_variant(comptime variant: Opcode) Fn {
            return struct {
                pub fn log(next_ip: InstructionPointer, gas: u32, stack_head: u16, frame: *evm.Frame) evm.Errors!void {
                    if (frame.is_static) return evm.Errors.WriteProtection;
                    const topic_count = variant.byte() - Opcode.LOG0.byte();
                    const num_args = 2 + topic_count;
                    // stackPop returns bottom-to-top: args[0] is deepest, args[n-1] is top.
                    // Stack layout: [...topics (deepest first)..., memSize, memOffset (top)]
                    const new_stack_head, const args = try frame.stackPop(stack_head, num_args, 0);
                    const mem_size = args[topic_count];
                    const mem_offset = args[topic_count + 1];
                    const available_gas = try frame.memory.growToFit(mem_offset, mem_size, gas);
                    const dynamic_gas = fork.log_size_gas_factor * @as(u32, @intCast(mem_size));

                    const data = frame.memory.slice(@truncate(mem_offset), @intCast(mem_size));
                    // Topics are deepest-first in args; reverse to get push order (topic1 first).
                    var topics: [4]u256 = undefined;
                    for (0..topic_count) |i| topics[i] = args[topic_count - 1 - i];

                    frame.evm.pushLog(frame.target, topics[0..topic_count], data);

                    return next(next_ip, available_gas, fork.constantGas(variant) + dynamic_gas, new_stack_head, frame);
                }
            }.log;
        }

        pub fn slotnum(next_ip: InstructionPointer, gas: u32, stack_head: u16, frame: *evm.Frame) evm.Errors!void {
            const new_stack_head = try frame.stackPush(stack_head, frame.context.slotnum);
            return next(next_ip, gas, fork.constantGas(.SLOTNUM), new_stack_head, frame);
        }

        pub fn entry(next_ip: InstructionPointer, gas: u32, stack_head: u16, frame: *evm.Frame) evm.Errors!void {
            return next(next_ip, gas, 0, stack_head, frame);
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
                .EXP = exp,
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
                .CLZ = clz,
                .JUMPDEST = jumpdest,
                .JUMP = jump,
                .JUMPI = jumpi,
                .GAS = opGas,
                .ADDRESS = address,
                .BALANCE = balance,
                .ORIGIN = origin,
                .CALLER = caller,
                .CALLVALUE = callvalue,
                .CALLDATALOAD = calldataload,
                .CALLDATASIZE = calldatasize,
                .CALLDATACOPY = calldatacopy,
                .CODESIZE = codesize,
                .CODECOPY = codecopy,
                .GASPRICE = gasprice,
                .PC = pc,
                .KECCAK256 = keccak256,
                .MSIZE = msize,
                .BLOCKHASH = blockhash,
                .COINBASE = coinbase,
                .TIMESTAMP = timestamp,
                .NUMBER = number,
                .PREVRANDO = random,
                .GASLIMIT = gaslimit,
                .MLOAD = mload,
                .MSTORE = mstore,
                .MSTORE8 = mstore8,
                .SLOAD = sload,
                .SSTORE = sstore,
                .TLOAD = tload,
                .TSTORE = tstore,
                .MCOPY = mcopy,
                .CREATE = create_variant(.CREATE),
                .CREATE2 = create_variant(.CREATE2),
                .CALL = call_variant(.CALL),
                .DELEGATECALL = call_variant(.DELEGATECALL),
                .CALLCODE = call_variant(.CALLCODE),
                .STATICCALL = call_variant(.STATICCALL),
                .RETURN = return_variant(.RETURN),
                .REVERT = return_variant(.REVERT),
                .EXTCODECOPY = extcodecopy,
                .EXTCODEHASH = extcodehash,
                .EXTCODESIZE = extcodesize,
                .RETURNDATASIZE = returndatasize,
                .RETURNDATACOPY = returndatacopy,
                .SELFDESTRUCT = selfdestruct,
                .BASEFEE = basefee,
                .BLOBHASH = blobhash,
                .BLOBBASEFEE = blobbasefee,
                .SELFBALANCE = selfbalance,
                .CHAINID = chainid,
                .LOG0 = log_variant(.LOG0),
                .LOG1 = log_variant(.LOG1),
                .LOG2 = log_variant(.LOG2),
                .LOG3 = log_variant(.LOG3),
                .LOG4 = log_variant(.LOG4),
            });
            inline for (0..33) |n| {
                t[Opcode.PUSH0.byte() + n] = pushN(n);
            }
            inline for (1..17) |n| {
                t[Opcode.DUP1.byte() + n - 1] = dupN(n);
            }
            inline for (1..17) |n| {
                t[Opcode.SWAP1.byte() + n - 1] = swapN(n);
            }

            if (cfg.fork.isEnabled(.Amsterdam)) {
                t[Opcode.SLOTNUM.byte()] = slotnum;
                t[Opcode.DUPN.byte()] = dupn;
                t[Opcode.SWAPN.byte()] = swapn;
                t[Opcode.EXCHANGE.byte()] = exchange;
            }

            return t;
        }
    };
}

fn tracing_hook(next_ip: InstructionPointer, gas: u32, stack_head: u16, frame: *evm.Frame) void {
    const log = struct {
        depth: usize,
        pc: u64,
        gas: []const u8,
        op: u8,
        stack: []u256,
        stateGas: []const u8,
    };
    const bytecode = frame.code.bytes;
    const pc = frame.code.programCounter(next_ip);
    std.debug.print("{f}\n", .{std.json.fmt(log{
        .depth = frame.depth,
        .pc = pc,
        .gas = &std.fmt.hex(@byteSwap(gas)),
        .op = if (pc < bytecode.len) bytecode[pc] else Opcode.STOP.byte(),
        .stack = frame.stack[0..stack_head],
        .stateGas = &std.fmt.hex(@byteSwap(frame.evm.state_gas_reservoir)),
    }, .{})});
}

/// Reads `bytes` as the leading bytes of a big-endian value of `total_size` bytes (1–32),
/// zero-padding the trailing bytes, and writes the result into `value`.
pub fn readBeSliceToU256(bytes: []const u8, total_size: usize, value: *u256) void {
    std.debug.assert(bytes.len <= total_size and total_size <= 32);
    value.* = 0;
    const buf: *[32]u8 = std.mem.asBytes(value);
    if (@import("builtin").cpu.arch.endian() == .big) {
        for (0..bytes.len) |i| buf[32 - total_size + i] = bytes[i];
    } else {
        for (0..bytes.len) |i| buf[total_size - 1 - i] = bytes[i];
    }
}
