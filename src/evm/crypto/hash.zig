const std = @import("std");
const build_options = @import("build_options");
const zkvm = @import("zkvm");

pub fn keccak256(data: []const u8) [32]u8 {
    var h: [32]u8 align(8) = undefined;
    if (build_options.platform == .zkvm) {
        if (zkvm.zkvm_keccak256(data.ptr, data.len, @ptrCast(&h)) != zkvm.ZKVM_EOK) {
            @panic("zkvm_keccak256 failed");
        }
        return h;
    }
    std.crypto.hash.sha3.Keccak256.hash(data, &h, .{});
    return h;
}

pub fn sha256(data: []const u8) [32]u8 {
    var h: [32]u8 align(8) = undefined;
    if (build_options.platform == .zkvm) {
        if (zkvm.zkvm_sha256(data.ptr, data.len, @ptrCast(&h)) != zkvm.ZKVM_EOK) {
            @panic("zkvm_sha256 failed");
        }
        return h;
    }
    std.crypto.hash.sha2.Sha256.hash(data, &h, .{});
    return h;
}
