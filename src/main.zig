const std = @import("std");
const evm = @import("evm.zig");
const ops = @import("ops.zig");
const spec = @import("spec.zig");
const Bytecode = @import("bytecode.zig").Bytecode;
const State = @import("state.zig").State;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}).init;
    const allocator = gpa.allocator();
    var context: evm.Context = std.mem.zeroes(evm.Context);
    var vm = try evm.EVM.init(allocator, &context);
    // const bytecodeRaw: []const u8 = &[_]u8{
    //     0x5b, // JUMPDEST
    //     0x5F, // PUSH0
    //     0x56, // JUMP
    // };
    //const bytecodeRaw: []const u8 = &[_]u8{ 91, 99, 1, 2, 3, 4, 100, 1, 2, 3, 4, 5, 80, 80, 101, 0, 0, 0, 0, 0, 0, 86, 96, 0, 86 };
    //const bytecodeRaw: []const u8 = &[_]u8{ 91, 96, 0, 128, 128, 128, 96, 4, 90, 80, 80, 80, 80, 80, 80, 96, 0, 86 };
    const bytecode_raw: []const u8 = &[_]u8{ 96, 1, 96, 1, 91, 128, 145, 1, 96, 4, 86 };

    const jump_table = ops.Ops(spec.Osaka).table();
    var bytecode = try Bytecode.init(allocator, bytecode_raw, jump_table);
    defer bytecode.deinit(allocator);
    const gas_limit = 100_000_000;
    var state = try State.init(allocator);
    defer state.deinit(allocator);
    try std.testing.expectError(evm.Errors.OutOfGas, vm.run(&state, bytecode, gas_limit, &[_]u8{}, 0));
}
