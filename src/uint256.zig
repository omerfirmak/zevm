/// Optimized u256 division via a 4-limb u64 algorithm.
const Limbs = [4]u64;

inline fn toLimbs(x: u256) Limbs {
    return .{
        @truncate(x),
        @truncate(x >> 64),
        @truncate(x >> 128),
        @truncate(x >> 192),
    };
}

inline fn fromLimbs(l: Limbs) u256 {
    return @as(u256, l[0]) |
        (@as(u256, l[1]) << 64) |
        (@as(u256, l[2]) << 128) |
        (@as(u256, l[3]) << 192);
}

inline fn limbsLt(a: Limbs, b: Limbs) bool {
    if (a[3] != b[3]) return a[3] < b[3];
    if (a[2] != b[2]) return a[2] < b[2];
    if (a[1] != b[1]) return a[1] < b[1];
    return a[0] < b[0];
}

inline fn limbsShr1(a: Limbs) Limbs {
    return .{
        (a[0] >> 1) | (a[1] << 63),
        (a[1] >> 1) | (a[2] << 63),
        (a[2] >> 1) | (a[3] << 63),
        a[3] >> 1,
    };
}

inline fn limbsSub(a: Limbs, b: Limbs) Limbs {
    var r: Limbs = undefined;
    var borrow: u64 = 0;
    inline for (0..4) |i| {
        // Adding 2^64 keeps the result in u128; bit 64 == 1 means no borrow.
        const d: u128 = (1 << 64) + @as(u128, a[i]) - @as(u128, b[i]) - @as(u128, borrow);
        r[i] = @truncate(d);
        borrow = 1 - @as(u64, @truncate(d >> 64));
    }
    return r;
}

/// Fast path when the divisor fits in a single u64 word.
fn divBy64(a: Limbs, d: u64) struct { q: Limbs, r: u64 } {
    var q: Limbs = .{ 0, 0, 0, 0 };
    var rem64: u64 = 0;
    var i: usize = 4;
    while (i > 0) {
        i -= 1;
        const dividend: u128 = (@as(u128, rem64) << 64) | a[i];
        q[i] = @truncate(dividend / d);
        rem64 = @truncate(dividend % d);
    }
    return .{ .q = q, .r = rem64 };
}

/// Divide `a` by `b`, returning both quotient and remainder.
/// Returns `{0, 0}` when `b == 0`.
pub fn divRem(a: u256, b: u256) struct { q: u256, r: u256 } {
    if (b == 0) return .{ .q = 0, .r = 0 };
    if (a < b) return .{ .q = 0, .r = a };

    const al = toLimbs(a);
    const bl = toLimbs(b);

    // Single-word divisor: use the fast 128-bit-per-step path.
    if (bl[3] == 0 and bl[2] == 0 and bl[1] == 0) {
        const res = divBy64(al, bl[0]);
        return .{ .q = fromLimbs(res.q), .r = res.r };
    }

    // Compute bit width of divisor (index of highest set bit + 1).
    // Bit widths are 1..256, so use usize; 256 would overflow u8.
    const div_bits: usize = if (bl[3] != 0)
        192 + 64 - @as(usize, @clz(bl[3]))
    else if (bl[2] != 0)
        128 + 64 - @as(usize, @clz(bl[2]))
    else
        64 + 64 - @as(usize, @clz(bl[1]));

    // Bit width of dividend.
    const dvd_bits: usize = if (al[3] != 0)
        192 + 64 - @as(usize, @clz(al[3]))
    else if (al[2] != 0)
        128 + 64 - @as(usize, @clz(al[2]))
    else if (al[1] != 0)
        64 + 64 - @as(usize, @clz(al[1]))
    else
        64 - @as(usize, @clz(al[0]));

    // Align divisor with the most-significant bit of the dividend, then
    // perform trial-subtraction long division (one quotient bit per step).
    // shift fits in u8: max = dvd_bits(256) - div_bits(65) = 191, since the
    // single-word path already handled bl[1]==0.
    var quotient: u256 = 0;
    var rem_l = al;
    var shift: u8 = @intCast(dvd_bits - div_bits);
    var shifted_l = toLimbs(b << shift);

    while (true) {
        if (!limbsLt(rem_l, shifted_l)) {
            rem_l = limbsSub(rem_l, shifted_l);
            quotient |= @as(u256, 1) << shift;
        }
        if (shift == 0) break;
        shift -= 1;
        shifted_l = limbsShr1(shifted_l);
    }

    return .{ .q = quotient, .r = fromLimbs(rem_l) };
}

pub inline fn div(a: u256, b: u256) u256 {
    return divRem(a, b).q;
}

pub inline fn rem(a: u256, b: u256) u256 {
    return divRem(a, b).r;
}
