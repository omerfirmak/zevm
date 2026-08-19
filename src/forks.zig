const std = @import("std");
const rlp = @import("rlp");

pub const Fork = enum(u8) {
    Osaka,
    BPO1,
    BPO2,
    Amsterdam,
};

pub const Schedule = struct {
    inner: @TypeOf(std.enums.directEnumArrayDefault(Fork, ?u64, @as(?u64, null), 0, .{})),

    fn init(comptime values: std.enums.EnumFieldStruct(Fork, ?u64, @as(?u64, null))) Schedule {
        return .{ .inner = std.enums.directEnumArrayDefault(Fork, ?u64, @as(?u64, null), 0, values) };
    }
};

pub const mainnet_prague_hash = [4]u8{ 0xc3, 0x76, 0xcf, 0x8b };
pub const mainnet_schedule = Schedule.init(.{
    .Osaka = 1764798551,
    .BPO1 = 1765290071,
    .BPO2 = 1767747671,
});

pub const Id = struct {
    hash: [4]u8,
    next: u64,
};

pub fn calculateId(initial_hash: [4]u8, schedule: *const Schedule, now: u64) Id {
    var crc: std.hash.Crc32 = .{ .crc = std.mem.readInt(u32, &initial_hash, .big) ^ 0xffff_ffff };
    var hash = initial_hash;
    for (0..schedule.inner.len) |i| {
        const time = schedule.inner[i] orelse continue;
        if (time > now) return .{ .hash = hash, .next = time };
        var blob: [8]u8 = undefined;
        std.mem.writeInt(u64, &blob, time, .big);
        crc.update(&blob);
        std.mem.writeInt(u32, &hash, crc.final(), .big);
    }
    return .{ .hash = hash, .next = 0 };
}

test "calculate" {
    const genesis = mainnet_prague_hash;
    // Last Prague block
    try std.testing.expectEqual(Id{ .hash = [4]u8{ 0xc3, 0x76, 0xcf, 0x8b }, .next = 1764798551 }, calculateId(genesis, &mainnet_schedule, 1764798550));
    // First Osaka block
    try std.testing.expectEqual(Id{ .hash = [4]u8{ 0x51, 0x67, 0xe2, 0xa6 }, .next = 1765290071 }, calculateId(genesis, &mainnet_schedule, 1764798551));
    // Last Osaka block
    try std.testing.expectEqual(Id{ .hash = [4]u8{ 0x51, 0x67, 0xe2, 0xa6 }, .next = 1765290071 }, calculateId(genesis, &mainnet_schedule, 1765290070));
    // First BPO1 block
    try std.testing.expectEqual(Id{ .hash = [4]u8{ 0xcb, 0xa2, 0xa1, 0xc0 }, .next = 1767747671 }, calculateId(genesis, &mainnet_schedule, 1765290071));
    // Last BPO1 block
    try std.testing.expectEqual(Id{ .hash = [4]u8{ 0xcb, 0xa2, 0xa1, 0xc0 }, .next = 1767747671 }, calculateId(genesis, &mainnet_schedule, 1767747670));
    // First BPO2 block
    try std.testing.expectEqual(Id{ .hash = [4]u8{ 0x07, 0xc9, 0x46, 0x2e }, .next = 0 }, calculateId(genesis, &mainnet_schedule, 1767747671));
    // Future BPO2 block
    try std.testing.expectEqual(Id{ .hash = [4]u8{ 0x07, 0xc9, 0x46, 0x2e }, .next = 0 }, calculateId(genesis, &mainnet_schedule, 2000000000));
}

test "encode" {
    var list = std.array_list.Managed(u8).init(std.testing.allocator);
    defer list.deinit();
    try rlp.serialize(Id, std.testing.allocator, .{ .hash = @bitCast(@as(u32, 0)), .next = 0 }, &list);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xc6, 0x84, 0x00, 0x00, 0x00, 0x00, 0x80 }, list.items);
    list.items.len = 0;
    try rlp.serialize(Id, std.testing.allocator, .{ .hash = [4]u8{ 0xde, 0xad, 0xbe, 0xef }, .next = 0xBADDCAFE }, &list);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xca, 0x84, 0xde, 0xad, 0xbe, 0xef, 0x84, 0xba, 0xdd, 0xca, 0xfe }, list.items);
    list.items.len = 0;
    try rlp.serialize(Id, std.testing.allocator, .{ .hash = @bitCast(@as(u32, std.math.maxInt(u32))), .next = std.math.maxInt(u64) }, &list);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xce, 0x84, 0xff, 0xff, 0xff, 0xff, 0x88, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff }, list.items);
}
