const std = @import("std");
const ssz = @import("ssz");
const rlp = @import("rlp");
const zevm = @import("zevm");
const types = @import("types.zig");
const CommittedState = @import("committed_state").CommittedState;

pub fn verify_ssz(allocator: std.mem.Allocator, input_bytes: []const u8) ![]const u8 {
    var input: types.StatelessInput = undefined;
    try ssz.deserialize(types.StatelessInput, input_bytes, &input, allocator);

    const res = try verify(allocator, input);

    var buf: std.ArrayList(u8) = .empty;
    try ssz.serialize(types.StatelessValidationResult, res, &buf, allocator);
    return buf.items;
}

pub fn verify(allocator: std.mem.Allocator, input: types.StatelessInput) !types.StatelessValidationResult {
    var headers = try allocator.alloc(zevm.types.BlockHeader, input.witness.headers.len);
    var ancestors = try allocator.alloc([32]u8, input.witness.headers.len);
    for (input.witness.headers, 0..) |header_bytes, i| {
        std.crypto.hash.sha3.Keccak256.hash(header_bytes, &ancestors[i], .{});
        _ = try rlp.deserialize(zevm.types.BlockHeader, allocator, header_bytes, &headers[i]);
        if (i > 0 and !std.mem.eql(u8, &ancestors[i], &headers[i].parent_hash)) {
            return error.InvalidAncestors;
        }
    }

    const parent = &headers[headers.len - 1];
    const bal: zevm.types.BlockAccessLists = undefined;
    _ = try CommittedState.init(
        allocator,
        parent.*.state_root,
        input.witness.state,
        input.witness.codes,
        &bal,
    );

    return error.NotImplemented;
}
