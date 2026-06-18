const std = @import("std");
const guest = @import("guest.zig");

pub fn main(init: std.process.Init) !void {
    const allocator = init.arena.allocator();

    var buf: [64]u8 = undefined;
    var stdin = std.Io.File.stdin().reader(init.io, &buf);
    const ssz_input = try stdin.interface.allocRemaining(allocator, .unlimited);
    const output = try guest.verify_ssz(allocator, ssz_input);

    if (output.len < 33 or output[32] == 0) return error.ValidationFailed;

    var out_buf: [256]u8 = undefined;
    var stdout = std.Io.File.stdout().writer(init.io, &out_buf);
    try stdout.interface.writeAll(output);
    try stdout.interface.flush();
}
