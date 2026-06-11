const std = @import("std");

pub fn keccak256(data: []const u8) [32]u8 {
    var h: [32]u8 = undefined;
    std.crypto.hash.sha3.Keccak256.hash(data, &h, .{});
    return h;
}

pub fn sha256(data: []const u8) [32]u8 {
    var h: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(data, &h, .{});
    return h;
}

pub const Sha256Hasher = std.crypto.hash.sha2.Sha256;
