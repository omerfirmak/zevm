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

    pub fn constantGas(self: *const Self, comptime op: Opcode) i32 {
        return @intCast(self.gas_table[@intFromEnum(op)]);
    }
};

// Osaka hardfork spec
pub const Osaka = Spec{
    .fork = .Osaka,
    .gas_table = std.enums.directEnumArrayDefault(Opcode, u32, 0, 256, .{}),
};
