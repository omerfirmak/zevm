// Copyright (c) 2025-2026 zevm authors
// SPDX-License-Identifier: MIT OR Apache-2.0

const std = @import("std");

pub const Shutdown = struct {
    const Self = @This();

    mask: std.posix.sigset_t,
    file: std.Io.File,

    pub fn init() !Self {
        var mask = std.posix.sigemptyset();
        std.posix.sigaddset(&mask, .INT);
        std.posix.sigaddset(&mask, .TERM);
        std.posix.sigprocmask(std.posix.SIG.BLOCK, &mask, null);
        return .{
            .mask = mask,
            .file = .{
                .handle = try std.posix.signalfd(-1, &mask, std.os.linux.SFD.CLOEXEC),
                .flags = .{ .nonblocking = false },
            },
        };
    }

    pub fn deinit(self: *Self, io: std.Io) void {
        self.file.close(io);
    }

    pub fn wait(self: *const Self, io: std.Io) !std.posix.SIG {
        var info: std.os.linux.signalfd_siginfo = undefined;
        if (try self.file.readStreaming(io, &.{std.mem.asBytes(&info)}) != @sizeOf(@TypeOf(info)))
            return error.ShortSignalRead;
        return @fromBackingInt(@intCast(info.signo));
    }

    pub fn unblock(self: *const Self) void {
        std.posix.sigprocmask(std.posix.SIG.UNBLOCK, &self.mask, null);
    }
};
