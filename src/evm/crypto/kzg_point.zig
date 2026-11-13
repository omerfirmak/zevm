// Copyright (c) 2025-2026 zevm authors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! EIP-4844 point verification needs the first trusted G2 power, not the blob or
//! FK20 proof-generation tables built by c-kzg's general setup loader.
const std = @import("std");
const kzg = @import("ckzg");
const c = kzg.c;
const setup = @import("trusted_setup");
const SpinLockOnce = @import("../sync.zig").SpinLockOnce;

var g2: [2]c.g2_t = undefined;
var once: SpinLockOnce(init) = .{};

fn init() void {
    for (&g2, 0..) |*point, i| {
        var affine: c.blst_p2_affine = undefined;
        const encoded = setup.g2_monomial_bytes[i * 96 ..][0..96];
        // These are embedded trusted-setup constants, never transaction input.
        if (c.blst_p2_uncompress(&affine, encoded.ptr) != c.BLST_SUCCESS or
            c.blst_p2_affine_is_inf(&affine) or !c.blst_p2_affine_in_g2(&affine))
            @panic("invalid embedded KZG G2 setup");
        c.blst_p2_from_affine(point, &affine);
    }
    if (!c.blst_p2_is_equal(&g2[0], c.blst_p2_generator())) @panic("invalid KZG monomial setup order");
}

pub fn verify(commitment: *const kzg.Bytes48, z: *const kzg.Bytes32, y: *const kzg.Bytes32, proof: *const kzg.Bytes48) bool {
    once.call();
    // In pinned c-kzg (68b445e8), verify_kzg_proof reads only G2[1]. The build
    // checks that dependency pin so upgrades require auditing this contract.
    // Keep this partial settings object private to that call: other APIs require
    // full settings, and free_trusted_setup must never own this static array.
    // c-kzg still checks canonical scalars, point encodings and subgroups.
    const settings = std.mem.zeroInit(c.KZGSettings, .{ .g2_values_monomial = &g2 });
    var ok = false;
    return c.verify_kzg_proof(&ok, commitment, z, y, proof, &settings) == c.C_KZG_OK and ok;
}

test "concurrent cold point verification publishes complete immutable G2 data" {
    // Run this before any other test calls verify. Failing here makes a warm
    // test-order regression explicit instead of silently losing cold coverage.
    try std.testing.expectEqual(@as(usize, 0), once.cur_state.load(.acquire));
    var full = try kzg.Settings.loadTrustedSetup(setup.g1_monomial_bytes, setup.g1_lagrange_bytes, setup.g2_monomial_bytes, 0);
    defer full.deinit();
    const blob = try std.testing.allocator.create(kzg.Blob);
    defer std.testing.allocator.destroy(blob);
    @memset(&blob.bytes, 0);
    blob.bytes[31] = 1;
    const commitment = try full.blobToKzgCommitment(blob);
    var z: kzg.Bytes32 = .{ .bytes = @splat(0) };
    z.bytes[31] = 7;
    const result = try full.computeKzgProof(blob, &z);
    try std.testing.expect(commitment.bytes[0] & 0x40 == 0);
    try std.testing.expect(result.proof.bytes[0] & 0x40 == 0);
    var wrong_y: kzg.Bytes32 = .{ .bytes = @splat(0) };
    if (std.mem.allEqual(u8, &result.y.bytes, 0)) wrong_y.bytes[31] = 1;
    const Jobs = struct {
        commitment: kzg.Bytes48,
        z: kzg.Bytes32,
        y: kzg.Bytes32,
        wrong_y: kzg.Bytes32,
        proof: kzg.Bytes48,
        ready: std.atomic.Value(usize) = .init(0),
        start: std.atomic.Value(bool) = .init(false),
        accepted: [8]bool = @splat(false),

        fn run(self: *@This(), index: usize) void {
            _ = self.ready.fetchAdd(1, .acq_rel);
            while (!self.start.load(.acquire)) std.atomic.spinLoopHint();
            self.accepted[index] = verify(&self.commitment, &self.z, &self.y, &self.proof) and
                !verify(&self.commitment, &self.z, &self.wrong_y, &self.proof);
        }
    };
    var jobs: Jobs = .{ .commitment = commitment, .z = z, .y = result.y, .wrong_y = wrong_y, .proof = result.proof };
    var threads: [8]std.Thread = undefined;
    var spawned: usize = 0;
    errdefer {
        jobs.start.store(true, .release);
        for (threads[0..spawned]) |thread| thread.join();
    }
    for (&threads, 0..) |*thread, i| {
        thread.* = try std.Thread.spawn(.{}, Jobs.run, .{ &jobs, i });
        spawned += 1;
    }
    while (jobs.ready.load(.acquire) != threads.len) std.atomic.spinLoopHint();
    jobs.start.store(true, .release);
    for (threads) |thread| thread.join();
    spawned = 0;
    for (jobs.accepted) |accepted| try std.testing.expect(accepted);
}

test "point verifier agrees with full c-kzg setup for nonconstant and zero polynomials" {
    var full = try kzg.Settings.loadTrustedSetup(setup.g1_monomial_bytes, setup.g1_lagrange_bytes, setup.g2_monomial_bytes, 0);
    defer full.deinit();
    const blob = try std.testing.allocator.create(kzg.Blob);
    defer std.testing.allocator.destroy(blob);
    for (0..3) |case| {
        @memset(&blob.bytes, 0);
        if (case != 0) {
            // Sparse nonconstant evaluation vectors produce non-infinity
            // commitments/proofs, unlike the zero polynomial alone.
            blob.bytes[case * 32 - 1] = @intCast(case);
        }
        const commitment = try full.blobToKzgCommitment(blob);
        var z: kzg.Bytes32 = .{ .bytes = @splat(0) };
        z.bytes[31] = @intCast(7 + case);
        const result = try full.computeKzgProof(blob, &z);
        if (case != 0) {
            try std.testing.expect(commitment.bytes[0] & 0x40 == 0);
            try std.testing.expect(result.proof.bytes[0] & 0x40 == 0);
        }
        try std.testing.expect(try full.verifyKzgProof(&commitment, &z, &result.y, &result.proof));
        try std.testing.expect(verify(&commitment, &z, &result.y, &result.proof));

        var wrong_y: kzg.Bytes32 = .{ .bytes = @splat(0) };
        if (std.mem.allEqual(u8, &result.y.bytes, 0)) wrong_y.bytes[31] = 1;
        try std.testing.expect(!try full.verifyKzgProof(&commitment, &z, &wrong_y, &result.proof));
        try std.testing.expect(!verify(&commitment, &z, &wrong_y, &result.proof));
        const scalar_out_of_range: kzg.Bytes32 = .{ .bytes = @splat(0xff) };
        try std.testing.expect(!verify(&commitment, &scalar_out_of_range, &result.y, &result.proof));
        try std.testing.expect(!verify(&commitment, &z, &scalar_out_of_range, &result.proof));
        const bad_point: kzg.Bytes48 = .{ .bytes = @splat(0xff) };
        try std.testing.expect(!verify(&bad_point, &z, &result.y, &result.proof));
        try std.testing.expect(!verify(&commitment, &z, &result.y, &bad_point));
    }
}
