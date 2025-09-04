const std = @import("std");
const ops = @import("ops.zig");
const Opcode = @import("opcode.zig").Opcode;

// Represents a contract's code. Also stores threaded representation
// and valid jump destinations that the EVM utilizes
pub const Bytecode = @This();

pub const InstructionPointer = [*]?ops.FnOpaquePtr;

// Raw bytecode of the contract
bytecode: []const u8,
// Threaded code of the bytecode with pointers to opcode handlers
// Uses an opaque type to avoid a reference loop,
threadedCode: []?ops.FnOpaquePtr,

// Creates a new Bytecode instance by first building a threaded code from the given
// raw bytecode and jumptable
pub fn init(gpa: std.mem.Allocator, bytecode: []const u8, jumpTable: [256]ops.Fn) !Bytecode {
    var threadedCode = try gpa.alloc(?ops.Fn, bytecode.len + 1);
    threadedCode[threadedCode.len - 1] = jumpTable[@intFromEnum(Opcode.STOP)];
    var pc: usize = 0;
    while (pc < bytecode.len) : (pc += 1) {
        const opcode = bytecode[pc];
        threadedCode[pc] = jumpTable[opcode];
        // Skip push data, leave the function pointer null
        if (opcode >= @intFromEnum(Opcode.PUSH1) and opcode <= @intFromEnum(Opcode.PUSH32)) {
            const dataLen = opcode - @intFromEnum(Opcode.PUSH1) + 1;
            const dataEnd = @min(bytecode.len, pc + dataLen + 1);
            // Fill positions of PUSH data bytes with null function pointers
            for (threadedCode[pc + 1 .. dataEnd]) |*slot| {
                slot.* = null;
            }
            // land on the last data byte; loop increment moves to next opcode
            pc = dataEnd - 1;
        }
    }

    return .{
        .bytecode = bytecode,
        .threadedCode = @ptrCast(threadedCode),
    };
}

pub fn deinit(self: *Bytecode, gpa: std.mem.Allocator) void {
    gpa.free(self.threadedCode);
}

// Checks if the given program counter is a valid jump destionation
pub fn isValidJumpDest(self: *Bytecode, pc: u256) ?InstructionPointer {
    if (pc >= self.bytecode.len) {
        @branchHint(.unlikely);
        return null;
    }
    const truncatedPc: usize = @intCast(pc);
    if (self.threadedCode[truncatedPc] == null or
        self.bytecode[truncatedPc] != @intFromEnum(Opcode.JUMPDEST))
    {
        @branchHint(.unlikely);
        return null;
    }
    return self.threadedCode[truncatedPc..].ptr;
}

// Fills bytes read from the bytecode to the given value and clears the upper bytes that were not used
pub fn readBytesToValue(self: *Bytecode, ip: InstructionPointer, comptime size: usize, value: *u256) void {
    comptime std.debug.assert(size <= 32);

    const start = ip - self.threadedCode.ptr;
    const end = @min(self.bytecode.len, start + size);
    const readSize = end - start;

    value.* = 0;
    const buf: *[32]u8 = std.mem.asBytes(value);
    if (@import("builtin").cpu.arch.endian() == .big) {
        for (32 - readSize..32) |index| {
            buf[index] = self.bytecode[start + index];
        }
    } else {
        for (0..readSize) |index| {
            buf[index] = self.bytecode[end - index - 1];
        }
    }
}

pub fn safeSlice(self: *Bytecode, index: u256, size: u64) []const u8 {
    if (index >= self.bytecode.len) {
        return &[_]u8{};
    }
    const readSize = @min(self.bytecode.len - index, size);
    return self.bytecode[@intCast(index)..@intCast(index + readSize)];
}

pub fn programCounter(self: *Bytecode, ip: InstructionPointer) u64 {
    return ip - self.threadedCode.ptr;
}
