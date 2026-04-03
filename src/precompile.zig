const std = @import("std");
const evm = @import("evm.zig");
const mem = @import("memory.zig");
const secp256k1 = @import("zig-eth-secp256k1");
const Ripemd160 = @import("crypto/ripemd160.zig").Ripemd160;
const Spec = @import("spec.zig").Spec;

pub const Result = struct {
    return_size: usize,
    remaining_gas: u31,
    err: ?evm.Errors,
};

pub const Handler = *const fn (
    gas: u31,
    calldata: []const u8,
    return_buffer: []u8,
) Result;

pub const Precompiles = enum(u9) {
    ecrecover = 0x01,
    sha2_256 = 0x02,
    ripemd_160 = 0x03,
    identity = 0x04,
    modexp = 0x05,
    ecadd = 0x06,
    ecmul = 0x07,
    ecpairing = 0x08,
    blake2f = 0x09,
    point_eval = 0x0a,
    bls12_g1add = 0x0b,
    bls12_g1msm = 0x0c,
    bls12_g2add = 0x0d,
    bls12_g2msm = 0x0e,
    bls12_pairing_check = 0x0f,
    bls12_map_fp_to_g1 = 0x10,
    bls12_map_fp2_to_g2 = 0x11,
    p256verify = 0x100,
};

pub fn Handlers(comptime fork: Spec) type {
    return struct {
        pub fn unimplemented(
            gas: u31,
            _: []const u8,
            _: []u8,
        ) Result {
            return .{ .return_size = 0, .remaining_gas = gas, .err = null };
        }

        pub fn identity(
            gas: u31,
            calldata: []const u8,
            return_buffer: []u8,
        ) Result {
            const cost = mem.toWordSize(calldata.len) * fork.identity_per_word_gas + fork.identity_base_gas;
            if (gas < cost) {
                return .{ .return_size = 0, .remaining_gas = 0, .err = evm.Errors.OutOfGas };
            }
            @memcpy(return_buffer[0..calldata.len], calldata);
            return .{ .return_size = calldata.len, .remaining_gas = gas - cost, .err = null };
        }

        pub fn sha2_256(
            gas: u31,
            calldata: []const u8,
            return_buffer: []u8,
        ) Result {
            const cost = mem.toWordSize(calldata.len) * fork.sha2256_per_word_gas + fork.sha2256_per_word_gas;
            if (gas < cost) {
                return .{ .return_size = 0, .remaining_gas = 0, .err = evm.Errors.OutOfGas };
            }

            const digest_length = std.crypto.hash.sha2.Sha256.digest_length;
            std.crypto.hash.sha2.Sha256.hash(calldata, return_buffer[0..digest_length], .{});
            return .{ .return_size = digest_length, .remaining_gas = gas - cost, .err = null };
        }

        pub fn ripemd_160(
            gas: u31,
            calldata: []const u8,
            return_buffer: []u8,
        ) Result {
            const cost = mem.toWordSize(calldata.len) * fork.ripemd160_per_word_gas + fork.ripemd160_base_gas;
            if (gas < cost) {
                return .{ .return_size = 0, .remaining_gas = 0, .err = evm.Errors.OutOfGas };
            }

            @memset(return_buffer[0..12], 0);
            Ripemd160.hash(calldata, return_buffer[12 .. 12 + Ripemd160.digest_length], .{});
            return .{ .return_size = 32, .remaining_gas = gas - cost, .err = null };
        }

        pub fn ecrecover(
            gas: u31,
            calldata: []const u8,
            return_buffer: []u8,
        ) Result {
            if (gas < fork.ecrecover_gas) {
                return .{ .return_size = 0, .remaining_gas = 0, .err = evm.Errors.OutOfGas };
            }
            const remaining_gas = gas - fork.ecrecover_gas;
            const err_result: Result = .{ .return_size = 0, .remaining_gas = remaining_gas, .err = null };
            const curve = secp256k1.Secp256k1.init() catch unreachable;

            var msg: secp256k1.Message = [_]u8{0} ** 32;
            var sig: secp256k1.Signature = [_]u8{0} ** 65;

            if (calldata.len > 0) {
                @branchHint(.likely);
                const msg_end = @min(32, calldata.len);
                @memcpy(msg[0..msg_end], calldata[0..msg_end]);
            }

            if (calldata.len > 32) {
                @branchHint(.likely);
                // v is a big-endian u256 at bytes 32..64; high 31 bytes must be zero, low byte must be 27 or 28
                for (32..@min(63, calldata.len)) |i| {
                    if (calldata[i] != 0) return err_result;
                }
            }
            if (calldata.len > 63) {
                @branchHint(.likely);
                const v = calldata[63];
                if (v != 27 and v != 28) return err_result;
                sig[64] = v - 27;
            } else {
                return err_result;
            }

            if (calldata.len > 64) {
                @branchHint(.likely);
                const rs_end = @min(128, calldata.len);
                const rs_len = rs_end - 64;
                @memcpy(sig[0..rs_len], calldata[64..rs_end]);
            }

            const pubkey = curve.recoverPubkey(msg, sig) catch {
                return err_result;
            };

            // Keccak256 of uncompressed pubkey (skip 0x04 prefix byte), take last 20 bytes as address
            var pubkey_hash: [32]u8 = undefined;
            std.crypto.hash.sha3.Keccak256.hash(pubkey[1..65], &pubkey_hash, .{});
            @memset(return_buffer[0..12], 0);
            @memcpy(return_buffer[12..32], pubkey_hash[12..32]);

            return .{ .return_size = 32, .remaining_gas = remaining_gas, .err = null };
        }

        pub fn p256verify(
            gas: u31,
            calldata: []const u8,
            return_buffer: []u8,
        ) Result {
            if (gas < fork.p256verify_gas) {
                return .{ .return_size = 0, .remaining_gas = 0, .err = evm.Errors.OutOfGas };
            }
            const remaining_gas = gas - fork.p256verify_gas;
            const err_result: Result = .{ .return_size = 0, .remaining_gas = remaining_gas, .err = null };

            // Input must be exactly 160 bytes: hash(32) || r(32) || s(32) || qx(32) || qy(32)
            if (calldata.len != 160) return err_result;

            const P256 = std.crypto.ecc.P256;
            const Scalar = P256.scalar.Scalar;

            const hash = calldata[0..32];
            const r_bytes = calldata[32..64];
            const s_bytes = calldata[64..96];
            const qx_bytes = calldata[96..128];
            const qy_bytes = calldata[128..160];

            // r and s must be in (0, n)
            const r = Scalar.fromBytes(r_bytes.*, .big) catch return err_result;
            if (r.isZero()) return err_result;
            const s = Scalar.fromBytes(s_bytes.*, .big) catch return err_result;
            if (s.isZero()) return err_result;

            // Parse and validate public key — rejects if not on curve, not canonical, or identity
            const Q = P256.fromSerializedAffineCoordinates(qx_bytes.*, qy_bytes.*, .big) catch
                return err_result;
            Q.rejectIdentity() catch return err_result;

            // ECDSA verification: R' = s^{-1}*hash*G + s^{-1}*r*Q
            // Reduce hash mod n via fromBytes48 (hash is 32 bytes, may exceed n)
            var hash_padded: [48]u8 = [_]u8{0} ** 48;
            @memcpy(hash_padded[16..48], hash);
            const e = Scalar.fromBytes48(hash_padded, .big);
            const s_inv = s.invert();
            const u_1 = s_inv.mul(e).toBytes(.big);
            const u_2 = s_inv.mul(r).toBytes(.big);

            const R = P256.basePoint.mulDoubleBasePublic(u_1, Q, u_2, .big) catch
                return err_result;
            R.rejectIdentity() catch return err_result;

            // R.x mod n must equal r (mod n comparison per EIP-7951)
            var rx_padded: [48]u8 = [_]u8{0} ** 48;
            @memcpy(rx_padded[16..48], &R.affineCoordinates().x.toBytes(.big));
            const r_check = Scalar.fromBytes48(rx_padded, .big).toBytes(.big);
            if (!std.mem.eql(u8, &r_check, r_bytes)) return err_result;

            @memset(return_buffer[0..31], 0);
            return_buffer[31] = 1;
            return .{ .return_size = 32, .remaining_gas = remaining_gas, .err = null };
        }

        pub fn table() [257]?Handler {
            return std.enums.directEnumArrayDefault(Precompiles, ?Handler, @as(?Handler, null), 257, .{
                .ecrecover = ecrecover,
                .sha2_256 = sha2_256,
                .ripemd_160 = ripemd_160,
                .identity = identity,
                .modexp = unimplemented,
                .ecadd = unimplemented,
                .ecmul = unimplemented,
                .ecpairing = unimplemented,
                .blake2f = unimplemented,
                .point_eval = unimplemented,
                .bls12_g1add = unimplemented,
                .bls12_g1msm = unimplemented,
                .bls12_g2add = unimplemented,
                .bls12_g2msm = unimplemented,
                .bls12_pairing_check = unimplemented,
                .bls12_map_fp_to_g1 = unimplemented,
                .bls12_map_fp2_to_g2 = unimplemented,
                .p256verify = p256verify,
            });
        }
    };
}
