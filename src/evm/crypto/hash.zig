const std = @import("std");
const build_options = @import("build_options");
const zkvm = @import("zkvm");

pub const Sha256 = struct {
    pub const digest_length = 32;
    pub const block_length = 64;
    pub const Options = struct {};

    const max_msg = 1024;
    buf: [max_msg]u8 align(8) = undefined,
    len: usize = 0,

    pub fn init(_: Options) Sha256 {
        return .{};
    }

    pub fn update(d: *Sha256, b: []const u8) void {
        if (d.len + b.len > max_msg) @panic("Sha256: message exceeds 1 KiB budget");
        @memcpy(d.buf[d.len..][0..b.len], b);
        d.len += b.len;
    }

    pub fn final(d: *Sha256, out: *[digest_length]u8) void {
        Sha256.hash(d.buf[0..d.len], out, .{});
    }

    pub fn finalResult(d: *Sha256) [digest_length]u8 {
        var result: [digest_length]u8 = undefined;
        d.final(&result);
        return result;
    }

    pub fn hash(b: []const u8, out: *[digest_length]u8, _: Options) void {
        // SSZ precomputes zero-subtree hashes at comptime, the zkvm accelerator
        // is an extern fn and can't run there, so fall back to std crypto.
        if (@inComptime()) {
            std.crypto.hash.sha2.Sha256.hash(b, out, .{});
            return;
        }
        out.* = sha256(b);
    }
};

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
