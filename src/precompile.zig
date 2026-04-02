const std = @import("std");
const evm = @import("evm.zig");
const mem = @import("memory.zig");
const Ripemd160 = @import("crypto/ripemd160.zig").Ripemd160;
const Spec = @import("spec.zig").Spec;

pub const PrecompileResult = struct {
    return_size: usize,
    remaining_gas: u31,
    err: ?evm.Errors,
};

pub const Handler = *const fn (
    gas: u31,
    calldata: []const u8,
    return_buffer: []u8,
) PrecompileResult;

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
        ) PrecompileResult {
            return .{ .return_size = 0, .remaining_gas = gas, .err = null };
        }

        pub fn identity(
            gas: u31,
            calldata: []const u8,
            return_buffer: []u8,
        ) PrecompileResult {
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
        ) PrecompileResult {
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
        ) PrecompileResult {
            const cost = mem.toWordSize(calldata.len) * fork.ripemd160_per_word_gas + fork.ripemd160_base_gas;
            if (gas < cost) {
                return .{ .return_size = 0, .remaining_gas = 0, .err = evm.Errors.OutOfGas };
            }

            @memset(return_buffer[0..12], 0);
            Ripemd160.hash(calldata, return_buffer[12 .. 12 + Ripemd160.digest_length], .{});
            return .{ .return_size = 32, .remaining_gas = gas - cost, .err = null };
        }

        pub fn table() [257]?Handler {
            return std.enums.directEnumArrayDefault(Precompiles, ?Handler, @as(?Handler, null), 257, .{
                .ecrecover = unimplemented,
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
                .p256verify = unimplemented,
            });
        }
    };
}
