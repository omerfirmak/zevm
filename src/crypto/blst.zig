const std = @import("std");
const blst = @import("blst");

const c = blst.c;
const fp_modulus = parseHex48("1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab");

pub const Limb = c.limb_t;
pub const Scalar = [32]u8;
pub const PairingProduct = c.fp12;
pub const scalar_bits = 256;
pub const g1_input_size = 128;
pub const g2_input_size = 256;
pub const scalar_size = 32;
pub const g1_msm_pair_size = g1_input_size + scalar_size;
pub const g2_msm_pair_size = g2_input_size + scalar_size;
pub const pairing_pair_size = g1_input_size + g2_input_size;

pub const Fp = extern struct {
    l: [6]Limb = std.mem.zeroes([6]Limb),
};

pub const Fp2 = extern struct {
    fp: [2]Fp = std.mem.zeroes([2]Fp),
};

pub const G1Affine = extern struct {
    x: Fp = std.mem.zeroes(Fp),
    y: Fp = std.mem.zeroes(Fp),

    pub fn infinity() G1Affine {
        return std.mem.zeroes(G1Affine);
    }
};

pub const G2Affine = extern struct {
    x: Fp2 = std.mem.zeroes(Fp2),
    y: Fp2 = std.mem.zeroes(Fp2),

    pub fn infinity() G2Affine {
        return std.mem.zeroes(G2Affine);
    }
};

const G1 = extern struct {
    x: Fp = std.mem.zeroes(Fp),
    y: Fp = std.mem.zeroes(Fp),
    z: Fp = std.mem.zeroes(Fp),
};

const G2 = extern struct {
    x: Fp2 = std.mem.zeroes(Fp2),
    y: Fp2 = std.mem.zeroes(Fp2),
    z: Fp2 = std.mem.zeroes(Fp2),
};

fn parseHex48(comptime hex: []const u8) [48]u8 {
    var out: [48]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex) catch unreachable;
    return out;
}

fn isZero(bytes: []const u8) bool {
    for (bytes) |byte| {
        if (byte != 0) return false;
    }
    return true;
}

pub fn decodeScalar(encoded: []const u8) ?Scalar {
    if (encoded.len != scalar_size) return null;
    var out: Scalar = undefined;
    for (encoded, 0..) |byte, i| {
        out[scalar_size - 1 - i] = byte;
    }
    return out;
}

pub fn decodeFp(encoded: []const u8) ?Fp {
    if (encoded.len != 64) return null;
    if (!isZero(encoded[0..16])) return null;
    if (std.mem.order(u8, encoded[16..64], &fp_modulus) != .lt) return null;
    var out: Fp = std.mem.zeroes(Fp);
    c.fp_from_bendian(@ptrCast(&out), encoded[16..64].ptr);
    return out;
}

pub fn decodeFp2(encoded: []const u8) ?Fp2 {
    if (encoded.len != 128) return null;
    const c0 = decodeFp(encoded[0..64]) orelse return null;
    const c1 = decodeFp(encoded[64..128]) orelse return null;
    return .{ .fp = .{ c0, c1 } };
}

pub fn encodeFp(out: []u8, value: *const Fp) void {
    std.debug.assert(out.len == 64);
    @memset(out[0..16], 0);
    c.bendian_from_fp(out[16..64].ptr, @ptrCast(value));
}

pub fn encodeFp2(out: []u8, value: *const Fp2) void {
    std.debug.assert(out.len == 128);
    encodeFp(out[0..64], &value.fp[0]);
    encodeFp(out[64..128], &value.fp[1]);
}

pub fn decodeG1Affine(encoded: []const u8, subgroup_check: bool) ?G1Affine {
    if (encoded.len != g1_input_size) return null;
    if (isZero(encoded)) return G1Affine.infinity();
    const point: G1Affine = .{
        .x = decodeFp(encoded[0..64]) orelse return null,
        .y = decodeFp(encoded[64..128]) orelse return null,
    };
    if (!g1OnCurve(&point)) return null;
    if (subgroup_check and !g1InSubgroup(&point)) return null;
    return point;
}

pub fn decodeG2Affine(encoded: []const u8, subgroup_check: bool) ?G2Affine {
    if (encoded.len != g2_input_size) return null;
    if (isZero(encoded)) return G2Affine.infinity();
    const point: G2Affine = .{
        .x = decodeFp2(encoded[0..128]) orelse return null,
        .y = decodeFp2(encoded[128..256]) orelse return null,
    };
    if (!g2OnCurve(&point)) return null;
    if (subgroup_check and !g2InSubgroup(&point)) return null;
    return point;
}

pub fn encodeG1Affine(out: []u8, point: *const G1Affine) usize {
    std.debug.assert(out.len >= g1_input_size);
    if (g1IsInfinity(point)) {
        @memset(out[0..g1_input_size], 0);
        return g1_input_size;
    }
    encodeFp(out[0..64], &point.x);
    encodeFp(out[64..128], &point.y);
    return g1_input_size;
}

pub fn encodeG2Affine(out: []u8, point: *const G2Affine) usize {
    std.debug.assert(out.len >= g2_input_size);
    if (g2IsInfinity(point)) {
        @memset(out[0..g2_input_size], 0);
        return g2_input_size;
    }
    encodeFp2(out[0..128], &point.x);
    encodeFp2(out[128..256], &point.y);
    return g2_input_size;
}

pub fn g1OnCurve(point: *const G1Affine) bool {
    return c.p1_affine_on_curve(@ptrCast(point));
}

pub fn g1InSubgroup(point: *const G1Affine) bool {
    return c.p1_affine_in_g1(@ptrCast(point));
}

pub fn g1IsInfinity(point: *const G1Affine) bool {
    return c.p1_affine_is_inf(@ptrCast(point));
}

pub fn g2OnCurve(point: *const G2Affine) bool {
    return c.p2_affine_on_curve(@ptrCast(point));
}

pub fn g2InSubgroup(point: *const G2Affine) bool {
    return c.p2_affine_in_g2(@ptrCast(point));
}

pub fn g2IsInfinity(point: *const G2Affine) bool {
    return c.p2_affine_is_inf(@ptrCast(point));
}

pub fn g1Add(out: *G1Affine, a: *const G1Affine, b: *const G1Affine) void {
    var acc: G1 = std.mem.zeroes(G1);
    c.p1_from_affine(@ptrCast(&acc), @ptrCast(a));
    c.p1_add_or_double_affine(@ptrCast(&acc), @ptrCast(&acc), @ptrCast(b));
    c.p1_to_affine(@ptrCast(out), @ptrCast(&acc));
}

pub fn g2Add(out: *G2Affine, a: *const G2Affine, b: *const G2Affine) void {
    var acc: G2 = std.mem.zeroes(G2);
    c.p2_from_affine(@ptrCast(&acc), @ptrCast(a));
    c.p2_add_or_double_affine(@ptrCast(&acc), @ptrCast(&acc), @ptrCast(b));
    c.p2_to_affine(@ptrCast(out), @ptrCast(&acc));
}

pub fn g1Mul(out: *G1Affine, point: *const G1Affine, scalar: *const Scalar) void {
    var base: G1 = std.mem.zeroes(G1);
    var product: G1 = std.mem.zeroes(G1);
    c.p1_from_affine(@ptrCast(&base), @ptrCast(point));
    c.p1_mult(@ptrCast(&product), @ptrCast(&base), scalar.ptr, scalar_bits);
    c.p1_to_affine(@ptrCast(out), @ptrCast(&product));
}

pub fn g2Mul(out: *G2Affine, point: *const G2Affine, scalar: *const Scalar) void {
    var base: G2 = std.mem.zeroes(G2);
    var product: G2 = std.mem.zeroes(G2);
    c.p2_from_affine(@ptrCast(&base), @ptrCast(point));
    c.p2_mult(@ptrCast(&product), @ptrCast(&base), scalar.ptr, scalar_bits);
    c.p2_to_affine(@ptrCast(out), @ptrCast(&product));
}

pub fn g1MsmAccumulate(acc: *G1Affine, point: *const G1Affine, scalar: *const Scalar, first: bool) void {
    if (first) {
        g1Mul(acc, point, scalar);
        return;
    }
    var term: G1Affine = undefined;
    g1Mul(&term, point, scalar);
    g1Add(acc, acc, &term);
}

pub fn g2MsmAccumulate(acc: *G2Affine, point: *const G2Affine, scalar: *const Scalar, first: bool) void {
    if (first) {
        g2Mul(acc, point, scalar);
        return;
    }
    var term: G2Affine = undefined;
    g2Mul(&term, point, scalar);
    g2Add(acc, acc, &term);
}

pub fn pairingAccumulate(acc: *c.fp12, q: *const G2Affine, p: *const G1Affine, first: bool) void {
    var term: c.fp12 = std.mem.zeroes(c.fp12);
    c.miller_loop(&term, @ptrCast(q), @ptrCast(p));
    if (first) {
        acc.* = term;
    } else {
        var tmp: c.fp12 = std.mem.zeroes(c.fp12);
        c.fp12_mul(&tmp, acc, &term);
        acc.* = tmp;
    }
}

pub fn pairingFinalVerify(acc: *const c.fp12) bool {
    var final_expanded: c.fp12 = std.mem.zeroes(c.fp12);
    c.final_exp(&final_expanded, acc);
    return c.fp12_is_one(&final_expanded);
}

pub fn mapFpToG1(out: *G1Affine, fp: *const Fp) void {
    var mapped: G1 = std.mem.zeroes(G1);
    c.map_to_g1(@ptrCast(&mapped), @ptrCast(fp), null);
    c.p1_to_affine(@ptrCast(out), @ptrCast(&mapped));
}

pub fn mapFp2ToG2(out: *G2Affine, fp2: *const Fp2) void {
    var mapped: G2 = std.mem.zeroes(G2);
    c.map_to_g2(@ptrCast(&mapped), @ptrCast(fp2), null);
    c.p2_to_affine(@ptrCast(out), @ptrCast(&mapped));
}
