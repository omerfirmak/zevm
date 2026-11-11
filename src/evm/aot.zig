// Copyright (c) 2025-2026 zevm authors
// SPDX-License-Identifier: MIT OR Apache-2.0

const std = @import("std");
const evm = @import("evm.zig");
const ops = @import("ops.zig");
const Opcode = @import("opcode.zig").Opcode;
const Config = @import("config.zig").Config;
const bytecode = @import("bytecode.zig");

const max_stack = 1024;
const max_region_blocks = 32;

const Block = struct {
    start_pc: usize,
    end_pc: usize,
    num_ops: usize = 0,
    total_static_gas: u64 = 0,
    stack_need: isize = 0,
    stack_peak: isize = 0,
    stack_net_delta: isize = 0,

    entry: bool,
    exit: union(enum) {
        fallthrough,
        // static and valid jump targets
        static_jump: usize,
        static_jumpi: usize,
    } = .fallthrough,

    fn init(start_pc: usize, entry: bool) Block {
        return .{ .start_pc = start_pc, .end_pc = start_pc, .entry = entry };
    }
};

// the blocks compiled together into one function
const Region = struct {
    const Member = struct { block: Block, height: isize };

    members: []const Member,
    peak_stack: usize,
};

fn Artifact(comptime cfg: Config, comptime code: []const u8) type {
    return struct {
        const O = ops.Ops(cfg);
        const table = O.table();

        const jumpdest_gas = cfg.fork.constantGas(.JUMPDEST);

        const BlockAnalysis = struct {
            is_jumpdest: [code.len]bool,
            blocks: [code.len]?Block,
        };

        const block_analysis = extractBlocks();

        fn extractBlocks() BlockAnalysis {
            @setEvalBranchQuota(100_000_000);
            var a: BlockAnalysis = .{ .is_jumpdest = @splat(false), .blocks = @splat(null) };

            var jd_pc: usize = 0;
            while (jd_pc < code.len) : (jd_pc += 1 + bytecode.immediateLength(cfg, code, jd_pc)) {
                a.is_jumpdest[jd_pc] = code[jd_pc] == Opcode.JUMPDEST.byte();
            }

            var cur = Block.init(0, true);
            var prev_pc: usize = 0;
            var next: usize = 0;
            var pc: usize = 0;
            while (pc < code.len) : ({
                prev_pc = pc;
                pc = next;
            }) {
                const op = code[pc];
                next = pc + 1 + bytecode.immediateLength(cfg, code, pc);

                const is_jump = op == Opcode.JUMP.byte() or op == Opcode.JUMPI.byte();
                const jump_target = if (is_jump) staticTarget(prev_pc, &a.is_jumpdest) else null;
                const compiled = !is_jump or jump_target != null;

                const pops, const pushes = (if (compiled) stackEffect(op) else null) orelse {
                    closeBlock(&a, cur, pc); // fallback to the interpreter
                    cur = Block.init(next, true);
                    continue;
                };

                cur.num_ops += 1;
                cur.total_static_gas += cfg.fork.gas_table[op];

                cur.stack_need = @max(cur.stack_need, pops - cur.stack_net_delta);
                cur.stack_net_delta += pushes - pops;
                cur.stack_peak = @max(cur.stack_peak, cur.stack_net_delta);

                switch (op) {
                    Opcode.JUMPDEST.byte() => {
                        closeBlock(&a, cur, next);
                        cur = Block.init(next, true);
                    },
                    Opcode.JUMP.byte(), Opcode.JUMPI.byte() => {
                        const target = jump_target.?;
                        if (op == Opcode.JUMP.byte()) {
                            cur.total_static_gas += jumpdest_gas;
                            cur.exit = .{ .static_jump = target };
                        } else {
                            cur.exit = .{ .static_jumpi = target };
                        }
                        closeBlock(&a, cur, next);
                        cur = Block.init(next, false); // cannot be jumped into by the interpreter
                    },
                    else => {},
                }
            }
            closeBlock(&a, cur, code.len); // eof
            return a;
        }

        fn closeBlock(a: *BlockAnalysis, blk: Block, end_pc: usize) void {
            if (blk.num_ops == 0) return;
            a.blocks[blk.start_pc] = blk;
            a.blocks[blk.start_pc].?.end_pc = end_pc;
        }

        fn staticTarget(pc: usize, is_jumpdest: *const [code.len]bool) ?usize {
            const op = code[pc];
            if (op < Opcode.PUSH0.byte() or op > Opcode.PUSH32.byte()) return null;
            const v = pushValue(pc);
            if (v >= code.len or !is_jumpdest[@intCast(v)]) return null;
            return @as(usize, @intCast(v)) + 1;
        }

        fn pushValue(pc: usize) u256 {
            var v: u256 = undefined;
            ops.readBeSliceToU256(code[pc + 1 ..], code[pc] - Opcode.PUSH0.byte(), &v);
            return v;
        }

        // Collects the region starting at `entry`
        fn regionAt(entry: Block) Region {
            @setEvalBranchQuota(100_000_000);

            var members: [max_region_blocks]Region.Member = undefined;
            members[0] = .{ .block = entry, .height = 0 };
            var n: usize = 1;
            var i: usize = 0;
            while (i < n) : (i += 1) {
                const height = members[i].height + members[i].block.stack_net_delta;
                for (staticSuccessors(members[i].block)) |succ| {
                    const blk = succ orelse continue;
                    const present = for (members[0..n]) |m| {
                        if (m.block.start_pc == blk.start_pc) break true;
                    } else false;
                    // The window only holds what was on the stack at entry + what
                    // the region pushed, so a member can't read below that
                    const in_window = entry.stack_need + height >= blk.stack_need;
                    if (!present and in_window and n < members.len) {
                        members[n] = .{ .block = blk, .height = height };
                        n += 1;
                    }
                }
            }

            var peak_stack = entry.stack_need;
            for (members[0..n]) |m| peak_stack = @max(peak_stack, entry.stack_need + m.height + m.block.stack_peak);

            const final = members[0..n].*;
            return .{ .members = &final, .peak_stack = @intCast(peak_stack) };
        }

        fn staticSuccessors(blk: Block) [2]?Block {
            const taken: ?usize, const not_taken: ?usize = switch (blk.exit) {
                .fallthrough => .{ null, blk.end_pc },
                .static_jump => |target| .{ target, null },
                .static_jumpi => |target| .{ target, blk.end_pc },
            };
            return .{ blockStartingAt(taken), blockStartingAt(not_taken) };
        }

        fn blockStartingAt(pc: ?usize) ?Block {
            const p = pc orelse return null;
            return if (p < code.len) block_analysis.blocks[p] else null;
        }

        fn canReach(from: Block, to: Block) bool {
            @setEvalBranchQuota(100_000_000);
            var seen: [code.len]bool = @splat(false);
            var queue: [code.len]Block = undefined;
            queue[0] = from;
            seen[from.start_pc] = true;
            var n: usize = 1;
            var i: usize = 0;
            while (i < n) : (i += 1) {
                for (staticSuccessors(queue[i])) |succ| {
                    const blk = succ orelse continue;
                    if (blk.start_pc == to.start_pc) return true;
                    if (seen[blk.start_pc]) continue;
                    seen[blk.start_pc] = true;
                    queue[n] = blk;
                    n += 1;
                }
            }
            return false;
        }

        // The function compiled for the region starting at `entry_pc`
        fn RegionFn(comptime entry_pc: usize) type {
            return struct {
                const entry = block_analysis.blocks[entry_pc].?;
                const region = regionAt(entry);

                fn memberAt(pc: usize, height: isize) ?usize {
                    for (region.members, 0..) |m, i| {
                        if (m.block.start_pc == pc and m.height == height) return i;
                    }
                    return null;
                }

                pub fn run(ip: bytecode.InstructionPointer, gas_in: u64, head: evm.StackPtr, frame: *evm.Frame) evm.Errors!void {
                    @setEvalBranchQuota(100_000_000);

                    const len = frame.stackLen(head);
                    if (entry.stack_need > 0 and len < entry.stack_need) {
                        @branchHint(.cold);
                        return evm.Errors.StackUnderflow;
                    }

                    // The local copy of the top of the stack. It never escapes this function, so LLVM keeps it in registers.
                    const base = head - entry.stack_need;
                    var window: [region.peak_stack]u256 = undefined;
                    inline for (0..entry.stack_need) |i| window[i] = base[i];
                    var gas = gas_in;

                    sw: switch (@as(usize, 0)) {
                        inline 0...region.members.len - 1 => |member_index| {
                            const m = region.members[member_index];
                            const next_height = m.height + m.block.stack_net_delta;
                            const next_pc = switch (m.block.exit) {
                                .static_jump => |target| target,
                                .fallthrough, .static_jumpi => m.block.end_pc,
                            };

                            if (gas < m.block.total_static_gas) {
                                @branchHint(.unlikely);
                                return evm.Errors.OutOfGas;
                            }
                            gas -= m.block.total_static_gas;

                            const top = m.height + m.block.stack_peak;
                            if (top > 0) {
                                if (len > max_stack - @as(usize, @intCast(top))) {
                                    @branchHint(.cold);
                                    return evm.Errors.StackOverflow;
                                }
                            }

                            const at: usize = @intCast(entry.stack_need + m.height - m.block.stack_need);
                            execute(m.block, window[at..][0..@intCast(m.block.stack_need + m.block.stack_peak)]);

                            if (m.block.exit == .static_jumpi) {
                                const end: usize = @intCast(entry.stack_need + next_height);
                                if (window[end] != 0) {
                                    if (gas < jumpdest_gas) {
                                        @branchHint(.unlikely);
                                        return evm.Errors.OutOfGas;
                                    }
                                    gas -= jumpdest_gas;
                                    const taken_pc = m.block.exit.static_jumpi;
                                    if (comptime memberAt(taken_pc, next_height)) |next_member_index| continue :sw next_member_index;
                                    return yield(taken_pc, next_height, &window, base, ip, gas, frame);
                                }
                            }
                            if (comptime memberAt(next_pc, next_height)) |next_member_index| continue :sw next_member_index;
                            return yield(next_pc, next_height, &window, base, ip, gas, frame);
                        },
                        else => unreachable,
                    }
                }

                inline fn yield(
                    comptime pc: usize,
                    comptime height: isize,
                    window: *[region.peak_stack]u256,
                    base: evm.StackPtr,
                    ip: bytecode.InstructionPointer,
                    gas: u64,
                    frame: *evm.Frame,
                ) evm.Errors!void {
                    const live: usize = @intCast(entry.stack_need + height);
                    inline for (0..live) |k| base[k] = window[k];
                    const next_ip = if (pc >= entry_pc) ip + (pc - entry_pc) else ip - (entry_pc - pc);
                    const args = .{ next_ip, gas, base + live, frame };
                    if (pc >= code.len) return @call(.always_tail, table[Opcode.STOP.byte()], args);
                    if (block_analysis.blocks[pc] != null) return @call(.always_tail, RegionFn(pc).run, args);
                    switch (comptime code[pc]) {
                        Opcode.DUPN.byte(), Opcode.SWAPN.byte(), Opcode.EXCHANGE.byte() => {
                            const f: ops.Fn = @ptrCast((next_ip - 1)[0].?);
                            return @call(.always_tail, f, args);
                        },
                        else => return @call(.always_tail, table[code[pc]], args),
                    }
                }
            };
        }

        // Generates the code for one block
        inline fn execute(comptime blk: Block, window: *[@intCast(blk.stack_need + blk.stack_peak)]u256) void {
            comptime var h: usize = @intCast(blk.stack_need);

            comptime var pc = blk.start_pc;
            inline while (pc < blk.end_pc) : (pc += comptime 1 + bytecode.immediateLength(cfg, code, pc)) {
                const op = code[pc];
                switch (op) {
                    Opcode.PUSH0.byte()...Opcode.PUSH32.byte(), Opcode.PC.byte() => {
                        window[h] = comptime if (op == Opcode.PC.byte()) pc else pushValue(pc);
                        h += 1;
                    },
                    Opcode.DUP1.byte()...Opcode.DUP16.byte() => {
                        window[h] = window[h - (op - Opcode.DUP1.byte() + 1)];
                        h += 1;
                    },
                    Opcode.SWAP1.byte()...Opcode.SWAP16.byte() => {
                        const other = h - 2 - (op - Opcode.SWAP1.byte());
                        const top = window[h - 1];
                        window[h - 1] = window[other];
                        window[other] = top;
                    },
                    Opcode.POP.byte() => h -= 1,
                    Opcode.JUMPDEST.byte(), Opcode.JUMP.byte(), Opcode.JUMPI.byte() => break,
                    else => {
                        const pops: usize = comptime @intCast(stackEffect(op).?[0]);
                        const a = window[h - 1];
                        const b = if (pops == 2) window[h - 2] else undefined;
                        window[h - pops] = switch (op) {
                            Opcode.ADD.byte() => O.coreAdd(a, b),
                            Opcode.MUL.byte() => O.coreMul(a, b),
                            Opcode.SUB.byte() => O.coreSub(a, b),
                            Opcode.DIV.byte() => O.coreDiv(a, b),
                            Opcode.MOD.byte() => O.coreMod(a, b),
                            Opcode.LT.byte() => O.coreLt(a, b),
                            Opcode.GT.byte() => O.coreGt(a, b),
                            Opcode.SLT.byte() => O.coreSlt(a, b),
                            Opcode.SGT.byte() => O.coreSgt(a, b),
                            Opcode.EQ.byte() => O.coreEq(a, b),
                            Opcode.ISZERO.byte() => O.coreIszero(a),
                            Opcode.AND.byte() => O.coreAnd(a, b),
                            Opcode.OR.byte() => O.coreOr(a, b),
                            Opcode.XOR.byte() => O.coreXor(a, b),
                            Opcode.NOT.byte() => O.coreNot(a),
                            Opcode.BYTE.byte() => O.coreByte(a, b),
                            Opcode.SHL.byte() => O.coreShl(a, b),
                            Opcode.SHR.byte() => O.coreShr(a, b),
                            Opcode.SAR.byte() => O.coreSar(a, b),
                            else => @compileError("no core function for this opcode"),
                        };
                        h = h - pops + 1;
                    },
                }
            }
        }
    };
}

// null if it isn't compiled and runs in the interpreter
fn stackEffect(op: u8) ?struct { isize, isize } {
    return switch (op) {
        Opcode.PUSH0.byte()...Opcode.PUSH32.byte(), Opcode.PC.byte() => .{ 0, 1 },
        Opcode.DUP1.byte()...Opcode.DUP16.byte() => |b| .{ b - Opcode.DUP1.byte() + 1, b - Opcode.DUP1.byte() + 2 },
        Opcode.SWAP1.byte()...Opcode.SWAP16.byte() => |b| .{ b - Opcode.SWAP1.byte() + 2, b - Opcode.SWAP1.byte() + 2 },
        Opcode.POP.byte() => .{ 1, 0 },
        Opcode.JUMPDEST.byte() => .{ 0, 0 },
        Opcode.JUMP.byte() => .{ 1, 0 },
        Opcode.JUMPI.byte() => .{ 2, 0 },
        Opcode.ADD.byte(), Opcode.MUL.byte(), Opcode.SUB.byte(), Opcode.DIV.byte(), Opcode.MOD.byte(), Opcode.LT.byte(), Opcode.GT.byte(), Opcode.SLT.byte(), Opcode.SGT.byte(), Opcode.EQ.byte(), Opcode.AND.byte(), Opcode.OR.byte(), Opcode.XOR.byte(), Opcode.BYTE.byte(), Opcode.SHL.byte(), Opcode.SHR.byte(), Opcode.SAR.byte() => .{ 2, 1 },
        Opcode.ISZERO.byte(), Opcode.NOT.byte() => .{ 1, 1 },
        else => null,
    };
}
