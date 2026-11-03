// Copyright (c) 2025-2026 zevm authors
// SPDX-License-Identifier: MIT OR Apache-2.0

const std = @import("std");

pub fn Number(comptime T: type) type {
    comptime std.debug.assert(@typeInfo(T) == .int and @typeInfo(T).int.signedness == .unsigned);
    return struct {
        const Self = @This();
        number: T,

        pub fn init(number: T) Self {
            return .{ .number = number };
        }

        pub fn jsonParse(
            allocator: std.mem.Allocator,
            source: anytype,
            options: std.json.ParseOptions,
        ) !Self {
            _ = allocator;
            _ = options;
            switch (try source.next()) {
                .string => |text| {
                    if (text.len < 3 or text[0] != '0' or (text[1] != 'x' and text[1] != 'X')) return error.InvalidNumber;
                    return .{ .number = try std.fmt.parseUnsigned(T, text[2..], 16) };
                },
                else => return error.UnexpectedToken,
            }
        }

        pub fn jsonStringify(
            self: *const Self,
            jws: anytype,
        ) !void {
            try jws.print("\"0x{x}\"", .{self.number});
        }
    };
}

pub fn Data(comptime N: usize) type {
    return struct {
        const Self = @This();
        bytes: [N]u8,

        pub fn jsonParse(allocator: std.mem.Allocator, source: anytype, options: std.json.ParseOptions) !Self {
            const text = try std.json.innerParse([]const u8, allocator, source, options);
            if (text.len != 2 + N * 2 or text[0] != '0' or (text[1] != 'x' and text[1] != 'X')) return error.LengthMismatch;
            var out: Self = undefined;
            _ = std.fmt.hexToBytes(&out.bytes, text[2..]) catch return error.InvalidCharacter;
            return out;
        }

        pub fn jsonStringify(self: *const Self, jws: anytype) !void {
            try jws.print("\"0x{x}\"", .{&self.bytes});
        }
    };
}

pub const Bytes = struct {
    const Self = @This();
    bytes: []const u8,

    pub fn jsonParse(allocator: std.mem.Allocator, source: anytype, options: std.json.ParseOptions) !Self {
        const text = try std.json.innerParse([]const u8, allocator, source, options);
        if (text.len < 2 or text[0] != '0' or (text[1] != 'x' and text[1] != 'X') or text.len % 2 != 0) return error.LengthMismatch;
        const bytes = try allocator.alloc(u8, (text.len - 2) / 2);
        _ = std.fmt.hexToBytes(bytes, text[2..]) catch return error.InvalidCharacter;
        return .{ .bytes = bytes };
    }

    pub fn jsonStringify(self: *const Self, jws: anytype) !void {
        try jws.print("\"0x{x}\"", .{self.bytes});
    }
};
