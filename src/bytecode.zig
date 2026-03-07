const std = @import("std");
const ops = @import("ops.zig");
const Opcode = @import("opcode.zig").Opcode;

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
pub fn init(gpa: std.mem.Allocator, bytes: []const u8, jump_table: [256]ops.Fn) !Bytecode {
    var threaded_code = try gpa.alloc(?ops.Fn, bytes.len + 1);
    threaded_code[threaded_code.len - 1] = jump_table[@intFromEnum(Opcode.STOP)];
    var pc: usize = 0;
    while (pc < bytes.len) : (pc += 1) {
        const opcode = bytes[pc];
        threaded_code[pc] = jump_table[opcode];
        // Skip push data, leave the function pointer null
        if (opcode >= @intFromEnum(Opcode.PUSH1) and opcode <= @intFromEnum(Opcode.PUSH32)) {
            const data_len = opcode - @intFromEnum(Opcode.PUSH1) + 1;
            const data_end = @min(bytes.len, pc + data_len + 1);
            // Fill positions of PUSH data bytes with null function pointers
            for (threaded_code[pc + 1 .. data_end]) |*slot| {
                slot.* = null;
            }
            // land on the last data byte; loop increment moves to next opcode
            pc = data_end - 1;
        }
    }

    return .{
        .bytes = bytes,
        .threaded_code = @ptrCast(threaded_code),
    };
}

pub fn deinit(self: *Bytecode, gpa: std.mem.Allocator) void {
    gpa.free(self.threaded_code);
}

// Checks if the given program counter is a valid jump destionation
pub fn isValidJumpDest(self: *Bytecode, pc: u256) ?InstructionPointer {
    if (pc >= self.bytes.len) {
        @branchHint(.unlikely);
        return null;
    }
    const truncated_pc: usize = @intCast(pc);
    if (self.threaded_code[truncated_pc] == null or
        self.bytes[truncated_pc] != @intFromEnum(Opcode.JUMPDEST))
    {
        @branchHint(.unlikely);
        return null;
    }
    return self.threaded_code[truncated_pc..].ptr;
}

// Fills bytes read from the bytecode to the given value and clears the upper bytes that were not used
pub fn readBytesToValue(self: *Bytecode, ip: InstructionPointer, comptime size: usize, value: *u256) void {
    comptime std.debug.assert(size <= 32);

    const start = ip - self.threaded_code.ptr;
    const end = @min(self.bytes.len, start + size);
    const read_size = end - start;

    value.* = 0;
    const buf: *[32]u8 = std.mem.asBytes(value);
    if (@import("builtin").cpu.arch.endian() == .big) {
        for (32 - read_size..32) |index| {
            buf[index] = self.bytes[start + index];
        }
    } else {
        for (0..read_size) |index| {
            buf[index] = self.bytes[end - index - 1];
        }
    }
}

pub fn safeSlice(self: *Bytecode, index: u256, size: u64) []const u8 {
    if (index >= self.bytes.len) {
        return &[_]u8{};
    }
    const read_size = @min(self.bytes.len - index, size);
    return self.bytes[@intCast(index)..@intCast(index + read_size)];
}

pub fn programCounter(self: *Bytecode, ip: InstructionPointer) u64 {
    return ip - self.threaded_code.ptr;
}
