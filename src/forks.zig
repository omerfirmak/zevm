const std = @import("std");
const rlp = @import("rlp");

pub const Fork = enum(u8) {
    Frontier,
    FrontierThawing,
    Homestead,
    DAO,
    TangerineWhistle,
    SpuriousDragon,
    Byzantium,
    Constantinople,
    Petersburg,
    Istanbul,
    MuirGlacier,
    Berlin,
    London,
    ArrowGlacier,
    GrayGlacier,
    Paris,
    Shanghai,
    Cancun,
    Prague,
    Osaka,
    BPO1,
    BPO2,
    BPO3,
    BPO4,
    BPO5,
    Amsterdam,
    Bogota,
};

pub const Schedule = struct {
    inner: @TypeOf(std.enums.directEnumArrayDefault(Fork, ?u64, @as(?u64, null), 0, .{})),

    fn init(comptime values: std.enums.EnumFieldStruct(Fork, ?u64, @as(?u64, null))) Schedule {
        return .{ .inner = std.enums.directEnumArrayDefault(Fork, ?u64, @as(?u64, null), 0, values) };
    }
};

pub const mainnet_schedule = Schedule.init(.{
    .Homestead = 1_150_000,
    .DAO = 1_920_000,
    .TangerineWhistle = 2_463_000,
    .SpuriousDragon = 2_675_000,
    .Byzantium = 4_370_000,
    .Constantinople = 7_280_000,
    .Petersburg = 7_280_000,
    .Istanbul = 9_069_000,
    .MuirGlacier = 9_200_000,
    .Berlin = 12_244_000,
    .London = 12_965_000,
    .ArrowGlacier = 13_773_000,
    .GrayGlacier = 15_050_000,
    .Shanghai = 1681338455,
    .Cancun = 1710338135,
    .Prague = 1746612311,
    .Osaka = 1764798551,
    .BPO1 = 1765290071,
    .BPO2 = 1767747671,
});

pub const Id = struct {
    hash: [4]u8,
    next: u64,
};

pub fn calculateId(genesis_hash: [32]u8, schedule: *const Schedule, now: u64) Id {
    var crc: std.hash.Crc32 = .init();
    crc.update(&genesis_hash);

    var hash: [4]u8 = undefined;
    std.mem.writeInt(u32, &hash, crc.final(), .big);
    var last: ?u64 = null;

    for (0..schedule.inner.len) |i| {
        const time = schedule.inner[i] orelse continue;
        if (time > now) return .{ .hash = hash, .next = time };
        if (last != null and last.? == time) continue;
        last = time;
        var blob: [8]u8 = undefined;
        std.mem.writeInt(u64, &blob, time, .big);
        crc.update(&blob);
        std.mem.writeInt(u32, &hash, crc.final(), .big);
    }
    return .{ .hash = hash, .next = 0 };
}

test "calculate from genesis" {
    const genesis = [32]u8{ 0xd4, 0xe5, 0x67, 0x40, 0xf8, 0x76, 0xae, 0xf8, 0xc0, 0x10, 0xb8, 0x6a, 0x40, 0xd5, 0xf5, 0x67, 0x45, 0xa1, 0x18, 0xd0, 0x90, 0x6a, 0x34, 0xe6, 0x9a, 0xec, 0x8c, 0x0d, 0xb1, 0xcb, 0x8f, 0xa3 };
    const schedule = &mainnet_schedule;
    // Unsynced
    try std.testing.expectEqual(Id{ .hash = [4]u8{ 0xfc, 0x64, 0xec, 0x04 }, .next = 1150000 }, calculateId(genesis, schedule, 0));
    // Last Frontier block
    try std.testing.expectEqual(Id{ .hash = [4]u8{ 0xfc, 0x64, 0xec, 0x04 }, .next = 1150000 }, calculateId(genesis, schedule, 1149999));
    // First Homestead block
    try std.testing.expectEqual(Id{ .hash = [4]u8{ 0x97, 0xc2, 0xc3, 0x4c }, .next = 1920000 }, calculateId(genesis, schedule, 1150000));
    // Last Homestead block
    try std.testing.expectEqual(Id{ .hash = [4]u8{ 0x97, 0xc2, 0xc3, 0x4c }, .next = 1920000 }, calculateId(genesis, schedule, 1919999));
    // First DAO block
    try std.testing.expectEqual(Id{ .hash = [4]u8{ 0x91, 0xd1, 0xf9, 0x48 }, .next = 2463000 }, calculateId(genesis, schedule, 1920000));
    // Last DAO block
    try std.testing.expectEqual(Id{ .hash = [4]u8{ 0x91, 0xd1, 0xf9, 0x48 }, .next = 2463000 }, calculateId(genesis, schedule, 2462999));
    // First Tangerine Whistle block
    try std.testing.expectEqual(Id{ .hash = [4]u8{ 0x7a, 0x64, 0xda, 0x13 }, .next = 2675000 }, calculateId(genesis, schedule, 2463000));
    // Last Tangerine Whistle block
    try std.testing.expectEqual(Id{ .hash = [4]u8{ 0x7a, 0x64, 0xda, 0x13 }, .next = 2675000 }, calculateId(genesis, schedule, 2674999));
    // First Spurious Dragon block
    try std.testing.expectEqual(Id{ .hash = [4]u8{ 0x3e, 0xdd, 0x5b, 0x10 }, .next = 4370000 }, calculateId(genesis, schedule, 2675000));
    // Last Spurious Dragon block
    try std.testing.expectEqual(Id{ .hash = [4]u8{ 0x3e, 0xdd, 0x5b, 0x10 }, .next = 4370000 }, calculateId(genesis, schedule, 4369999));
    // First Byzantium block
    try std.testing.expectEqual(Id{ .hash = [4]u8{ 0xa0, 0x0b, 0xc3, 0x24 }, .next = 7280000 }, calculateId(genesis, schedule, 4370000));
    // Last Byzantium block
    try std.testing.expectEqual(Id{ .hash = [4]u8{ 0xa0, 0x0b, 0xc3, 0x24 }, .next = 7280000 }, calculateId(genesis, schedule, 7279999));
    // First and last Constantinople, first Petersburg block
    try std.testing.expectEqual(Id{ .hash = [4]u8{ 0x66, 0x8d, 0xb0, 0xaf }, .next = 9069000 }, calculateId(genesis, schedule, 7280000));
    // Last Petersburg block
    try std.testing.expectEqual(Id{ .hash = [4]u8{ 0x66, 0x8d, 0xb0, 0xaf }, .next = 9069000 }, calculateId(genesis, schedule, 9068999));
    // First Istanbul and first Muir Glacier block
    try std.testing.expectEqual(Id{ .hash = [4]u8{ 0x87, 0x9d, 0x6e, 0x30 }, .next = 9200000 }, calculateId(genesis, schedule, 9069000));
    // Last Istanbul and first Muir Glacier block
    try std.testing.expectEqual(Id{ .hash = [4]u8{ 0x87, 0x9d, 0x6e, 0x30 }, .next = 9200000 }, calculateId(genesis, schedule, 9199999));
    // First Muir Glacier block
    try std.testing.expectEqual(Id{ .hash = [4]u8{ 0xe0, 0x29, 0xe9, 0x91 }, .next = 12244000 }, calculateId(genesis, schedule, 9200000));
    // Last Muir Glacier block
    try std.testing.expectEqual(Id{ .hash = [4]u8{ 0xe0, 0x29, 0xe9, 0x91 }, .next = 12244000 }, calculateId(genesis, schedule, 12243999));
    // First Berlin block
    try std.testing.expectEqual(Id{ .hash = [4]u8{ 0x0e, 0xb4, 0x40, 0xf6 }, .next = 12965000 }, calculateId(genesis, schedule, 12244000));
    // Last Berlin block
    try std.testing.expectEqual(Id{ .hash = [4]u8{ 0x0e, 0xb4, 0x40, 0xf6 }, .next = 12965000 }, calculateId(genesis, schedule, 12964999));
    // First London block
    try std.testing.expectEqual(Id{ .hash = [4]u8{ 0xb7, 0x15, 0x07, 0x7d }, .next = 13773000 }, calculateId(genesis, schedule, 12965000));
    // Last London block
    try std.testing.expectEqual(Id{ .hash = [4]u8{ 0xb7, 0x15, 0x07, 0x7d }, .next = 13773000 }, calculateId(genesis, schedule, 13772999));
    // First Arrow Glacier block
    try std.testing.expectEqual(Id{ .hash = [4]u8{ 0x20, 0xc3, 0x27, 0xfc }, .next = 15050000 }, calculateId(genesis, schedule, 13773000));
    // Last Arrow Glacier block
    try std.testing.expectEqual(Id{ .hash = [4]u8{ 0x20, 0xc3, 0x27, 0xfc }, .next = 15050000 }, calculateId(genesis, schedule, 15049999));
    // First Gray Glacier block
    try std.testing.expectEqual(Id{ .hash = [4]u8{ 0xf0, 0xaf, 0xd0, 0xe3 }, .next = 1681338455 }, calculateId(genesis, schedule, 15050000));
    // Last Gray Glacier block
    try std.testing.expectEqual(Id{ .hash = [4]u8{ 0xf0, 0xaf, 0xd0, 0xe3 }, .next = 1681338455 }, calculateId(genesis, schedule, 1681338454));
    // First Shanghai block
    try std.testing.expectEqual(Id{ .hash = [4]u8{ 0xdc, 0xe9, 0x6c, 0x2d }, .next = 1710338135 }, calculateId(genesis, schedule, 1681338455));
    // Last Shanghai block
    try std.testing.expectEqual(Id{ .hash = [4]u8{ 0xdc, 0xe9, 0x6c, 0x2d }, .next = 1710338135 }, calculateId(genesis, schedule, 1710338134));
    // First Cancun block
    try std.testing.expectEqual(Id{ .hash = [4]u8{ 0x9f, 0x3d, 0x22, 0x54 }, .next = 1746612311 }, calculateId(genesis, schedule, 1710338135));
    // Last Cancun block
    try std.testing.expectEqual(Id{ .hash = [4]u8{ 0x9f, 0x3d, 0x22, 0x54 }, .next = 1746612311 }, calculateId(genesis, schedule, 1746022486));
    // First Prague block
    try std.testing.expectEqual(Id{ .hash = [4]u8{ 0xc3, 0x76, 0xcf, 0x8b }, .next = 1764798551 }, calculateId(genesis, schedule, 1746612311));
    // Last Prague block
    try std.testing.expectEqual(Id{ .hash = [4]u8{ 0xc3, 0x76, 0xcf, 0x8b }, .next = 1764798551 }, calculateId(genesis, schedule, 1764798550));
    // First Osaka block
    try std.testing.expectEqual(Id{ .hash = [4]u8{ 0x51, 0x67, 0xe2, 0xa6 }, .next = 1765290071 }, calculateId(genesis, schedule, 1764798551));
    // Last Osaka block
    try std.testing.expectEqual(Id{ .hash = [4]u8{ 0x51, 0x67, 0xe2, 0xa6 }, .next = 1765290071 }, calculateId(genesis, schedule, 1765290070));
    // First BPO1 block
    try std.testing.expectEqual(Id{ .hash = [4]u8{ 0xcb, 0xa2, 0xa1, 0xc0 }, .next = 1767747671 }, calculateId(genesis, schedule, 1765290071));
    // Last BPO1 block
    try std.testing.expectEqual(Id{ .hash = [4]u8{ 0xcb, 0xa2, 0xa1, 0xc0 }, .next = 1767747671 }, calculateId(genesis, schedule, 1767747670));
    // First BPO2 block
    try std.testing.expectEqual(Id{ .hash = [4]u8{ 0x07, 0xc9, 0x46, 0x2e }, .next = 0 }, calculateId(genesis, schedule, 1767747671));
    // Future BPO2 block
    try std.testing.expectEqual(Id{ .hash = [4]u8{ 0x07, 0xc9, 0x46, 0x2e }, .next = 0 }, calculateId(genesis, schedule, 2000000000));
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
