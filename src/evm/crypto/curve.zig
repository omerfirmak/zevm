const std = @import("std");
const build_options = @import("build_options");
const zkvm = @import("zkvm");

const Curve = std.crypto.ecc.Secp256k1;
const Scalar = Curve.scalar.Scalar;
const Fe = Curve.Fe;

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

    var r_bytes: [32]u8 = undefined;
    var s_bytes: [32]u8 = undefined;
    std.mem.writeInt(u256, &r_bytes, r, .big);
    std.mem.writeInt(u256, &s_bytes, s, .big);

    // Reconstruct R: the curve point whose x-coordinate is r and whose
    // y-coordinate has parity matching the low bit of v.
    const r_fe = try Fe.fromBytes(r_bytes, .big);
    const r_y = try Curve.recoverY(r_fe, (v & 1) == 1);
    const R = try Curve.fromAffineCoordinates(.{ .x = r_fe, .y = r_y });

    // r and s must be in [1, n-1]
    const r_scalar = try Scalar.fromBytes(r_bytes, .big);
    const s_scalar = try Scalar.fromBytes(s_bytes, .big);
    if (r_scalar.isZero() or s_scalar.isZero()) return error.InvalidSignature;

    // hash is reduced mod n (EVM allows hash >= n, treating it as hash mod n)
    var hash_padded: [64]u8 = [_]u8{0} ** 64;
    @memcpy(hash_padded[32..64], &hash);
    const hash_scalar = Scalar.fromBytes64(hash_padded, .big);

    // r_inv = r^{-1} mod n
    const r_inv = r_scalar.invert();
    const u1_bytes = r_inv.mul(s_scalar).toBytes(.big);
    const u2_bytes = r_inv.mul(hash_scalar.neg()).toBytes(.big);

    // pubkey_point = u1*R + u2*G
    const pubkey_point = try Curve.mulDoubleBasePublic(R, u1_bytes, Curve.basePoint, u2_bytes, .big);
    try pubkey_point.rejectIdentity();

    return addressFromPubkey(pubkey_point.toUncompressedSec1());
}

pub fn addressFromPubkey(pubkey: [65]u8) u160 {
    const h = @import("hash.zig").keccak256(pubkey[1..65]);
    return std.mem.readInt(u160, h[12..32], .big);
}
