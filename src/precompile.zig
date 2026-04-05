const std = @import("std");
const evm = @import("evm.zig");
const mem = @import("memory.zig");
const secp256k1 = @import("zig-eth-secp256k1");
const bls12 = @import("crypto/blst.zig");
const Ripemd160 = @import("crypto/ripemd160.zig").Ripemd160;
const Spec = @import("spec.zig").Spec;

pub const Result = struct {
    return_size: usize = 0,
    remaining_gas: i32 = 0,
    err: ?evm.Errors = null,
};

const out_of_gas: Result = .{ .err = evm.Errors.OutOfGas };
const invalid_input: Result = .{ .err = evm.Errors.InvalidPrecompileInput };

pub const Handler = *const fn (
    gas: i32,
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

const bls12_g1_discounts = [_]u16{
    0,   1000, 949, 848, 797, 764, 750, 738, 728, 719, 712, 705, 698, 692, 687, 682, 677, 673, 669, 665, 661, 658, 654,
    651, 648,  645, 642, 640, 637, 635, 632, 630, 627, 625, 623, 621, 619, 617, 615, 613, 611, 609, 608, 606, 604, 603,
    601, 599,  598, 596, 595, 593, 592, 591, 589, 588, 586, 585, 584, 582, 581, 580, 579, 577, 576, 575, 574, 573, 572,
    570, 569,  568, 567, 566, 565, 564, 563, 562, 561, 560, 559, 558, 557, 556, 555, 554, 553, 552, 551, 550, 549, 548,
    547, 547,  546, 545, 544, 543, 542, 541, 540, 540, 539, 538, 537, 536, 536, 535, 534, 533, 532, 532, 531, 530, 529,
    528, 528,  527, 526, 525, 525, 524, 523, 522, 522, 521, 520, 520, 519,
};

const bls12_g2_discounts = [_]u16{
    0,   1000, 1000, 923, 884, 855, 832, 812, 796, 782, 770, 759, 749, 740, 732, 724, 717, 711, 704, 699, 693, 688, 683,
    679, 674,  670,  666, 663, 659, 655, 652, 649, 646, 643, 640, 637, 634, 632, 629, 627, 624, 622, 620, 618, 615, 613,
    611, 609,  607,  606, 604, 602, 600, 598, 597, 595, 593, 592, 590, 589, 587, 586, 584, 583, 582, 580, 579, 578, 576,
    575, 574,  573,  571, 570, 569, 568, 567, 566, 565, 563, 562, 561, 560, 559, 558, 557, 556, 555, 554, 553, 552, 552,
    551, 550,  549,  548, 547, 546, 545, 545, 544, 543, 542, 541, 541, 540, 539, 538, 537, 537, 536, 535, 535, 534, 533,
    532, 532,  531,  530, 530, 529, 528, 528, 527, 526, 526, 525, 524, 524,
};

pub fn Handlers(comptime fork: Spec) type {
    return struct {
        pub fn unimplemented(
            gas: i32,
            _: []const u8,
            _: []u8,
        ) Result {
            return .{ .remaining_gas = gas };
        }

        pub fn identity(
            gas: i32,
            calldata: []const u8,
            return_buffer: []u8,
        ) Result {
            const cost = mem.toWordSize(calldata.len) * fork.identity_per_word_gas + fork.identity_base_gas;
            if (gas < cost) return out_of_gas;
            @memcpy(return_buffer[0..calldata.len], calldata);
            return .{ .return_size = calldata.len, .remaining_gas = gas - cost };
        }

        pub fn sha2_256(
            gas: i32,
            calldata: []const u8,
            return_buffer: []u8,
        ) Result {
            const cost = mem.toWordSize(calldata.len) * fork.sha2256_per_word_gas + fork.sha2256_base_gas;
            if (gas < cost) return out_of_gas;

            const digest_length = std.crypto.hash.sha2.Sha256.digest_length;
            std.crypto.hash.sha2.Sha256.hash(calldata, return_buffer[0..digest_length], .{});
            return .{ .return_size = digest_length, .remaining_gas = gas - cost };
        }

        pub fn ripemd_160(
            gas: i32,
            calldata: []const u8,
            return_buffer: []u8,
        ) Result {
            const cost = mem.toWordSize(calldata.len) * fork.ripemd160_per_word_gas + fork.ripemd160_base_gas;
            if (gas < cost) return out_of_gas;

            @memset(return_buffer[0..12], 0);
            Ripemd160.hash(calldata, return_buffer[12 .. 12 + Ripemd160.digest_length], .{});
            return .{ .return_size = 32, .remaining_gas = gas - cost };
        }

        pub fn ecrecover(
            gas: i32,
            calldata: []const u8,
            return_buffer: []u8,
        ) Result {
            if (gas < fork.ecrecover_gas) return out_of_gas;
            const remaining_gas = gas - fork.ecrecover_gas;
            const bail: Result = .{ .remaining_gas = remaining_gas };

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
                    if (calldata[i] != 0) return bail;
                }
            }
            if (calldata.len > 63) {
                @branchHint(.likely);
                const v = calldata[63];
                if (v != 27 and v != 28) return bail;
                sig[64] = v - 27;
            } else return bail;

            if (calldata.len > 64) {
                @branchHint(.likely);
                const rs_end = @min(128, calldata.len);
                const rs_len = rs_end - 64;
                @memcpy(sig[0..rs_len], calldata[64..rs_end]);
            }

            const pubkey = curve.recoverPubkey(msg, sig) catch return bail;

            // Keccak256 of uncompressed pubkey (skip 0x04 prefix byte), take last 20 bytes as address
            var pubkey_hash: [32]u8 = undefined;
            std.crypto.hash.sha3.Keccak256.hash(pubkey[1..65], &pubkey_hash, .{});
            @memset(return_buffer[0..12], 0);
            @memcpy(return_buffer[12..32], pubkey_hash[12..32]);

            return .{ .return_size = 32, .remaining_gas = remaining_gas };
        }

        pub fn p256verify(
            gas: i32,
            calldata: []const u8,
            return_buffer: []u8,
        ) Result {
            if (gas < fork.p256verify_gas) {
                return .{ .return_size = 0, .remaining_gas = 0, .err = evm.Errors.OutOfGas };
            }
            const remaining_gas = gas - fork.p256verify_gas;
            const bail: Result = .{ .remaining_gas = remaining_gas };

            // Input must be exactly 160 bytes: hash(32) || r(32) || s(32) || qx(32) || qy(32)
            if (calldata.len != 160) return bail;

            const P256 = std.crypto.ecc.P256;
            const Scalar = P256.scalar.Scalar;

            const hash = calldata[0..32];
            const r_bytes = calldata[32..64];
            const s_bytes = calldata[64..96];
            const qx_bytes = calldata[96..128];
            const qy_bytes = calldata[128..160];

            // r and s must be in (0, n)
            const r = Scalar.fromBytes(r_bytes.*, .big) catch return bail;
            if (r.isZero()) return bail;
            const s = Scalar.fromBytes(s_bytes.*, .big) catch return bail;
            if (s.isZero()) return bail;

            // Parse and validate public key — rejects if not on curve, not canonical, or identity
            const Q = P256.fromSerializedAffineCoordinates(qx_bytes.*, qy_bytes.*, .big) catch
                return bail;
            Q.rejectIdentity() catch return bail;

            // ECDSA verification: R' = s^{-1}*hash*G + s^{-1}*r*Q
            // Reduce hash mod n via fromBytes48 (hash is 32 bytes, may exceed n)
            var hash_padded: [48]u8 = [_]u8{0} ** 48;
            @memcpy(hash_padded[16..48], hash);
            const e = Scalar.fromBytes48(hash_padded, .big);
            const s_inv = s.invert();
            const u_1 = s_inv.mul(e).toBytes(.big);
            const u_2 = s_inv.mul(r).toBytes(.big);

            const R = P256.basePoint.mulDoubleBasePublic(u_1, Q, u_2, .big) catch
                return bail;
            R.rejectIdentity() catch return bail;

            // R.x mod n must equal r (mod n comparison per EIP-7951)
            var rx_padded: [48]u8 = [_]u8{0} ** 48;
            @memcpy(rx_padded[16..48], &R.affineCoordinates().x.toBytes(.big));
            const r_check = Scalar.fromBytes48(rx_padded, .big).toBytes(.big);
            if (!std.mem.eql(u8, &r_check, r_bytes)) return bail;

            @memset(return_buffer[0..31], 0);
            return_buffer[31] = 1;
            return .{ .return_size = 32, .remaining_gas = remaining_gas };
        }

        pub fn bls12G1add(
            gas: i32,
            calldata: []const u8,
            return_buffer: []u8,
        ) Result {
            if (gas < fork.bls12_g1add_gas) return out_of_gas;
            if (calldata.len != bls12.g1_input_size * 2) return invalid_input;
            const a = bls12.decodeG1Affine(calldata[0..bls12.g1_input_size], false) orelse
                return invalid_input;
            const b = bls12.decodeG1Affine(calldata[bls12.g1_input_size .. bls12.g1_input_size * 2], false) orelse
                return invalid_input;
            var out: bls12.G1Affine = undefined;
            bls12.g1Add(&out, &a, &b);
            const return_size = bls12.encodeG1Affine(return_buffer, &out);
            return .{ .return_size = return_size, .remaining_gas = gas - fork.bls12_g1add_gas };
        }

        fn bls12MsmCost(input_len: usize, comptime pair_len: usize, comptime mul_cost: i32, comptime discounts: []const u16) i32 {
            const k = input_len / pair_len;
            if (k == 0) return 0;
            const discount = discounts[@min(k, discounts.len - 1)];
            const cost_u64 = @as(u64, k) * @as(u64, @intCast(mul_cost)) * @as(u64, discount) / 1000;
            return if (cost_u64 > std.math.maxInt(i32)) std.math.maxInt(i32) else @intCast(cost_u64);
        }

        pub fn bls12G1msm(
            gas: i32,
            calldata: []const u8,
            return_buffer: []u8,
        ) Result {
            const cost = bls12MsmCost(calldata.len, bls12.g1_msm_pair_size, fork.bls12_g1mul_gas, &bls12_g1_discounts);
            if (gas < cost) return out_of_gas;
            if (calldata.len == 0 or calldata.len % bls12.g1_msm_pair_size != 0) return invalid_input;

            const k = calldata.len / bls12.g1_msm_pair_size;
            var acc: bls12.G1Affine = undefined;
            var first = true;
            for (0..k) |i| {
                const offset = i * bls12.g1_msm_pair_size;
                const point = bls12.decodeG1Affine(calldata[offset .. offset + bls12.g1_input_size], true) orelse
                    return invalid_input;
                const scalar = bls12.decodeScalar(calldata[offset + bls12.g1_input_size .. offset + bls12.g1_msm_pair_size]) orelse
                    unreachable;
                bls12.g1MsmAccumulate(&acc, &point, &scalar, first);
                first = false;
            }
            const return_size = bls12.encodeG1Affine(return_buffer, &acc);
            return .{ .return_size = return_size, .remaining_gas = gas - cost };
        }

        pub fn bls12G2add(
            gas: i32,
            calldata: []const u8,
            return_buffer: []u8,
        ) Result {
            if (gas < fork.bls12_g2add_gas) return out_of_gas;
            if (calldata.len != bls12.g2_input_size * 2) return invalid_input;
            const a = bls12.decodeG2Affine(calldata[0..bls12.g2_input_size], false) orelse
                return invalid_input;
            const b = bls12.decodeG2Affine(calldata[bls12.g2_input_size .. bls12.g2_input_size * 2], false) orelse
                return invalid_input;
            var out: bls12.G2Affine = undefined;
            bls12.g2Add(&out, &a, &b);
            const return_size = bls12.encodeG2Affine(return_buffer, &out);
            return .{ .return_size = return_size, .remaining_gas = gas - fork.bls12_g2add_gas };
        }

        pub fn bls12G2msm(
            gas: i32,
            calldata: []const u8,
            return_buffer: []u8,
        ) Result {
            const cost = bls12MsmCost(calldata.len, bls12.g2_msm_pair_size, fork.bls12_g2mul_gas, &bls12_g2_discounts);
            if (gas < cost) return out_of_gas;
            if (calldata.len == 0 or calldata.len % bls12.g2_msm_pair_size != 0) return invalid_input;

            const k = calldata.len / bls12.g2_msm_pair_size;
            var acc: bls12.G2Affine = undefined;
            var first = true;
            for (0..k) |i| {
                const offset = i * bls12.g2_msm_pair_size;
                const point = bls12.decodeG2Affine(calldata[offset .. offset + bls12.g2_input_size], true) orelse
                    return invalid_input;
                const scalar = bls12.decodeScalar(calldata[offset + bls12.g2_input_size .. offset + bls12.g2_msm_pair_size]) orelse
                    unreachable;
                bls12.g2MsmAccumulate(&acc, &point, &scalar, first);
                first = false;
            }
            const return_size = bls12.encodeG2Affine(return_buffer, &acc);
            return .{ .return_size = return_size, .remaining_gas = gas - cost };
        }

        fn bls12PairingCost(input_len: usize, comptime pair_len: usize, comptime base_cost: i32, comptime per_pair_cost: i32) i32 {
            const k = input_len / pair_len;
            const cost_u64 = @as(u64, @intCast(base_cost)) + @as(u64, k) * @as(u64, @intCast(per_pair_cost));
            return if (cost_u64 > std.math.maxInt(i32)) std.math.maxInt(i32) else @intCast(cost_u64);
        }

        pub fn bls12PairingCheck(
            gas: i32,
            calldata: []const u8,
            return_buffer: []u8,
        ) Result {
            const cost = bls12PairingCost(
                calldata.len,
                bls12.pairing_pair_size,
                fork.bls12_pairing_base_gas,
                fork.bls12_pairing_per_pair_gas,
            );
            if (gas < cost) return out_of_gas;
            if (calldata.len == 0 or calldata.len % bls12.pairing_pair_size != 0) return invalid_input;

            const k = calldata.len / bls12.pairing_pair_size;
            var product: bls12.PairingProduct = std.mem.zeroes(bls12.PairingProduct);
            var first = true;
            for (0..k) |i| {
                const offset = i * bls12.pairing_pair_size;
                const p = bls12.decodeG1Affine(calldata[offset .. offset + bls12.g1_input_size], true) orelse
                    return invalid_input;
                const q = bls12.decodeG2Affine(calldata[offset + bls12.g1_input_size .. offset + bls12.pairing_pair_size], true) orelse
                    return invalid_input;
                bls12.pairingAccumulate(&product, &q, &p, first);
                first = false;
            }
            @memset(return_buffer[0..31], 0);
            return_buffer[31] = @intFromBool(bls12.pairingFinalVerify(&product));
            const return_size: usize = 32;
            return .{ .return_size = return_size, .remaining_gas = gas - cost };
        }

        pub fn bls12MapFpToG1(
            gas: i32,
            calldata: []const u8,
            return_buffer: []u8,
        ) Result {
            if (gas < fork.bls12_map_fp_to_g1_gas) return out_of_gas;
            if (calldata.len != 64) return invalid_input;
            const fp = bls12.decodeFp(calldata) orelse
                return invalid_input;
            var out: bls12.G1Affine = undefined;
            bls12.mapFpToG1(&out, &fp);
            const return_size = bls12.encodeG1Affine(return_buffer, &out);
            return .{ .return_size = return_size, .remaining_gas = gas - fork.bls12_map_fp_to_g1_gas };
        }

        pub fn bls12MapFp2ToG2(
            gas: i32,
            calldata: []const u8,
            return_buffer: []u8,
        ) Result {
            if (gas < fork.bls12_map_fp2_to_g2_gas) return out_of_gas;
            if (calldata.len != 128) return invalid_input;
            const fp2 = bls12.decodeFp2(calldata) orelse
                return invalid_input;
            var out: bls12.G2Affine = undefined;
            bls12.mapFp2ToG2(&out, &fp2);
            const return_size = bls12.encodeG2Affine(return_buffer, &out);
            return .{ .return_size = return_size, .remaining_gas = gas - fork.bls12_map_fp2_to_g2_gas };
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
                .bls12_g1add = bls12G1add,
                .bls12_g1msm = bls12G1msm,
                .bls12_g2add = bls12G2add,
                .bls12_g2msm = bls12G2msm,
                .bls12_pairing_check = bls12PairingCheck,
                .bls12_map_fp_to_g1 = bls12MapFpToG1,
                .bls12_map_fp2_to_g2 = bls12MapFp2ToG2,
                .p256verify = p256verify,
            });
        }
    };
}
