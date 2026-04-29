const std = @import("std");
const secp256k1 = @import("zig-eth-secp256k1");
const SpinLockOnce = @import("sync.zig").SpinLockOnce;

var curve_ctx: secp256k1.Secp256k1 = undefined;
var curve_once: SpinLockOnce(initCtx) = .{};
fn initCtx() void {
    curve_ctx = secp256k1.Secp256k1.init() catch @panic("secp256k1 init failed");
}

pub fn ecrecover(
    hash: [32]u8,
    v: u256,
    r: u256,
    s: u256,
) !u160 {
    curve_once.call();
    var sig: secp256k1.Signature = [_]u8{0} ** 65;
    std.mem.writeInt(u256, sig[0..32], r, .big);
    std.mem.writeInt(u256, sig[32..64], s, .big);
    sig[64] = @intCast(v & 1);
    const pubkey = try curve_ctx.recoverPubkey(hash, sig);

    var pubkey_hash: [32]u8 = undefined;
    std.crypto.hash.sha3.Keccak256.hash(pubkey[1..65], &pubkey_hash, .{});
    return std.mem.readInt(u160, pubkey_hash[12..32], .big);
}
