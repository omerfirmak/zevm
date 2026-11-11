// Copyright (c) 2025-2026 zevm authors
// SPDX-License-Identifier: MIT OR Apache-2.0

const std = @import("std");
const ops = @import("ops.zig");
const Opcode = @import("opcode.zig").Opcode;
const Config = @import("config.zig").Config;

// Represents a contract's code. Also stores threaded representation
// and valid jump destinations that the EVM utilizes
pub const Bytecode = @This();

pub const InstructionPointer = [*]?ops.FnOpaquePtr;

// Raw bytecode of the contract
bytes: []const u8,
// Threaded code of the bytecode with pointers to opcode handlers
// Uses an opaque type to avoid a reference loop,
threaded_code: []?ops.FnOpaquePtr,

// Creates a new Bytecode instance by first building a threaded code from the given
// raw bytecode and jumptable
pub fn init(gpa: std.mem.Allocator, bytes: []const u8, comptime cfg: Config) !Bytecode {
    const jump_table = comptime ops.Ops(cfg).table();
    var threaded_code = try gpa.alloc(?ops.Fn, bytes.len + 33);
    var pc: usize = 0;
    while (pc < bytes.len) {
        const opcode = bytes[pc];
        const imm_len = immediateLength(cfg, bytes, pc);
        threaded_code[pc] = jump_table[opcode];
        // Immediate bytes aren't instructions, leave their function pointers null
        @memset(threaded_code[pc + 1 ..][0..imm_len], null);

        switch (opcode) {
            // An immediate in the invalid range isn't skipped and the instruction is invalid
            Opcode.DUPN.byte(), Opcode.SWAPN.byte(), Opcode.EXCHANGE.byte() => if (cfg.fork.isEnabled(.Amsterdam) and
                imm_len == 0 and pc + 1 < bytes.len)
            {
                threaded_code[pc] = jump_table[Opcode.INVALID.byte()];
            },
            else => {},
        }
        pc += 1 + imm_len;
    }
    @memset(threaded_code[pc..], jump_table[Opcode.STOP.byte()]);

    return .{
        .bytes = bytes,
        .threaded_code = @ptrCast(threaded_code),
    };
}

pub fn deinit(self: *const Bytecode, gpa: std.mem.Allocator) void {
    gpa.free(self.threaded_code);
}

// Checks if the given program counter is a valid jump destionation
pub fn isValidJumpDest(self: *const Bytecode, pc: u256) ?InstructionPointer {
    if (pc >= self.bytes.len) {
        @branchHint(.unlikely);
        return null;
    }
    const truncated_pc: usize = @intCast(pc);
    if (self.threaded_code[truncated_pc] == null or
        self.bytes[truncated_pc] != Opcode.JUMPDEST.byte())
    {
        @branchHint(.unlikely);
        return null;
    }
    return self.threaded_code[truncated_pc..].ptr;
}

// Fills bytes read from the bytecode to the given value and clears the upper bytes that were not used
pub fn readBytesToValue(self: *const Bytecode, ip: InstructionPointer, comptime size: usize, value: *u256) void {
    comptime std.debug.assert(size <= 32);

    const start = ip - self.threaded_code.ptr;
    ops.readBeSliceToU256(self.bytes[start..], size, value);
}

pub fn readByte(self: *const Bytecode, ip: InstructionPointer) u8 {
    const offset: usize = ip - self.threaded_code.ptr;
    return if (offset < self.bytes.len) self.bytes[offset] else 0;
}

pub fn safeSlice(self: *const Bytecode, index: u256, size: u64) []const u8 {
    if (index >= self.bytes.len) {
        return &[_]u8{};
    }
    const read_size = @min(self.bytes.len - index, size);
    return self.bytes[@intCast(index)..@intCast(index + read_size)];
}

pub fn programCounter(self: *const Bytecode, ip: InstructionPointer) u64 {
    return ip - self.threaded_code.ptr;
}

pub fn immediateLength(comptime cfg: Config, bytecode: []const u8, pc: usize) usize {
    return switch (bytecode[pc]) {
        Opcode.PUSH0.byte()...Opcode.PUSH32.byte() => |b| b - Opcode.PUSH0.byte(),
        Opcode.DUPN.byte(), Opcode.SWAPN.byte(), Opcode.EXCHANGE.byte() => |b| {
            if (!cfg.fork.isEnabled(.Amsterdam) or pc + 1 >= bytecode.len) return 0;
            // An immediate in the invalid range isn't skipped: the opcode becomes INVALID.
            const invalid_low: u8 = if (b == Opcode.EXCHANGE.byte()) 0x52 else 0x5b;
            const imm = bytecode[pc + 1];
            return @intFromBool(!(invalid_low <= imm and imm <= 0x7f));
        },
        else => 0,
    };
}
