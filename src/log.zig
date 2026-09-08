const std = @import("std");

pub fn timestamped(
    comptime level: std.log.Level,
    comptime scope: @EnumLiteral(),
    comptime format: []const u8,
    args: anytype,
) void {
    const io = std.Options.debug_io;
    const us = @divFloor(std.Io.Clock.now(.real, io).toNanoseconds(), std.time.ns_per_us);
    const day_secs: u64 = @intCast(@mod(@divFloor(us, std.time.us_per_s), std.time.s_per_day));

    const prev = io.swapCancelProtection(.blocked);
    defer _ = io.swapCancelProtection(prev);

    var buffer: [512]u8 = undefined;
    const t = std.debug.lockStderr(&buffer).terminal();
    defer std.debug.unlockStderr();

    t.setColor(.dim) catch {};
    t.writer.print("{d:0>2}:{d:0>2}:{d:0>2}.{d:0>6} ", .{
        day_secs / 3600,
        (day_secs % 3600) / 60,
        day_secs % 60,
        @as(u64, @intCast(@mod(us, std.time.us_per_s))),
    }) catch return;
    t.setColor(.reset) catch {};

    std.log.defaultLogFileTerminal(level, scope, format, args, t) catch {};
}
