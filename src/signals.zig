// Copyright (c) 2025-2026 zevm authors
// SPDX-License-Identifier: MIT OR Apache-2.0

const std = @import("std");

pub const Shutdown = struct {
    const Self = @This();

    // self-pipe: the handler forwards the signal number so it can be awaited through Io.
    var write_fd: std.posix.fd_t = -1;

    file: std.Io.File,

    pub fn init() !Self {
        var fds: [2]std.posix.fd_t = undefined;
        if (std.c.pipe(&fds) != 0) return error.PipeFailed;
        write_fd = fds[1];
        setHandler(forward);
        return .{ .file = .{ .handle = fds[0], .flags = .{ .nonblocking = false } } };
    }

    pub fn deinit(self: *Self, io: std.Io) void {
        setHandler(std.posix.SIG.DFL);
        _ = std.c.close(write_fd);
        self.file.close(io);
    }

    pub fn wait(self: *const Self, io: std.Io) !std.posix.SIG {
        var signo: [1]u8 = undefined;
        if (try self.file.readStreaming(io, &.{&signo}) != 1)
            return error.ShortSignalRead;
        return @fromBackingInt(@intCast(signo[0]));
    }

    pub fn unblock(_: *const Self) void {
        setHandler(std.posix.SIG.DFL);
    }

    fn setHandler(handler: ?std.posix.Sigaction.handler_fn) void {
        const act: std.posix.Sigaction = .{
            .handler = .{ .handler = handler },
            .mask = std.posix.sigemptyset(),
            .flags = std.posix.SA.RESTART,
        };
        std.posix.sigaction(.INT, &act, null);
        std.posix.sigaction(.TERM, &act, null);
    }

    fn forward(sig: std.posix.SIG) callconv(.c) void {
        const signo: u8 = @intCast(@backingInt(sig));
        _ = std.c.write(write_fd, &[_]u8{signo}, 1);
    }
};
