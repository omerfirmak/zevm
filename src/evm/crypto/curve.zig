const std = @import("std");
const build_options = @import("build_options");
const secp256k1 = @import("zig-eth-secp256k1");
const zkvm = @import("zkvm");
const SpinLockOnce = @import("../sync.zig").SpinLockOnce;

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
    if (build_options.platform == .zkvm) {
        var msg: zkvm.zkvm_secp256k1_hash align(8) = undefined;
        msg.data = hash;
        var sig: zkvm.zkvm_secp256k1_signature align(8) = undefined;
        std.mem.writeInt(u256, sig.data[0..32], r, .big);
        std.mem.writeInt(u256, sig.data[32..64], s, .big);
        var out: zkvm.zkvm_secp256k1_pubkey align(8) = undefined;
        if (zkvm.zkvm_secp256k1_ecrecover(&msg, &sig, @intCast(v & 1), &out) != zkvm.ZKVM_EOK) {
            return error.RecoverFailed;
        }
        const h = @import("hash.zig").keccak256(&out.data);
        return std.mem.readInt(u160, h[12..32], .big);
    }

    curve_once.call();
    var sig: secp256k1.Signature = [_]u8{0} ** 65;
    std.mem.writeInt(u256, sig[0..32], r, .big);
    std.mem.writeInt(u256, sig[32..64], s, .big);
    sig[64] = @intCast(v & 1);
    const pubkey = try curve_ctx.recoverPubkey(hash, sig);

    return addressFromPubkey(pubkey);
}

pub fn addressFromPubkey(pubkey: [65]u8) u160 {
    const h = @import("hash.zig").keccak256(pubkey[1..65]);
    return std.mem.readInt(u160, h[12..32], .big);
}
