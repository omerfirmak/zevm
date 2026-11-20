// Copyright (c) 2025-2026 zevm authors
// SPDX-License-Identifier: MIT OR Apache-2.0

const std = @import("std");

pub fn FnCancelOnErr(comptime func: anytype) fn (std.meta.ArgsTuple(@TypeOf(func))) std.Io.Cancelable!void {
    return struct {
        fn run(args: std.meta.ArgsTuple(@TypeOf(func))) std.Io.Cancelable!void {
            @call(.auto, func, args) catch return error.Canceled;
        }
    }.run;
}

pub fn FnReportErr(comptime func: anytype) fn (std.meta.ArgsTuple(@TypeOf(func)), *?anyerror) std.Io.Cancelable!void {
    return struct {
        fn run(args: std.meta.ArgsTuple(@TypeOf(func)), err: *?anyerror) std.Io.Cancelable!void {
            @call(.auto, func, args) catch |e| {
                if (e == error.Canceled) return error.Canceled;
                err.* = e;
            };
        }
    }.run;
}

pub fn spawn(
    group: *std.Io.Group,
    io: std.Io,
    comptime func: anytype,
    args: std.meta.ArgsTuple(@TypeOf(func)),
    err: *?anyerror,
) void {
    group.async(io, FnReportErr(func), .{ args, err });
}

pub fn spawnCancelOnErr(
    group: *std.Io.Group,
    io: std.Io,
    comptime func: anytype,
    args: std.meta.ArgsTuple(@TypeOf(func)),
) void {
    group.async(io, FnCancelOnErr(func), .{args});
}
