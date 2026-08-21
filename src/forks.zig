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

pub const glamsterdam_devnet8_schedule = Schedule.init(.{
    .Amsterdam = 1_787_212_224,
});

pub const Id = struct {
    hash: [4]u8,
    next: u64,
};

pub const IdFilter = struct {
    const timestamp_threshold = 1_000_000_000;

    sums: [std.meta.tags(Fork).len + 1]?[4]u8,
    schedule: Schedule,

    pub fn init(genesis_hash: [32]u8, schedule: *const Schedule) IdFilter {
        var sums: [std.meta.tags(Fork).len + 1]?[4]u8 = @splat(null);
        var sum: [4]u8 = undefined;

        var crc: std.hash.Crc32 = .init();
        crc.update(&genesis_hash);

        std.mem.writeInt(u32, &sum, crc.final(), .big);
        sums[0] = sum;

        var last: ?u64 = null;
        for (0..schedule.inner.len) |i| {
            const time = schedule.inner[i] orelse continue;
            if (last != null and last.? == time) continue;
            last = time;
            var blob: [8]u8 = undefined;
            std.mem.writeInt(u64, &blob, time, .big);
            crc.update(&blob);
            std.mem.writeInt(u32, &sum, crc.final(), .big);
            sums[i + 1] = sum;
        }

        return .{
            .sums = sums,
            .schedule = schedule.*,
        };
    }

    pub fn currentId(self: *const IdFilter, head: u64, time: u64) Id {
        var hash = self.sums[0].?;
        for (0..self.schedule.inner.len) |i| {
            const fork = self.schedule.inner[i] orelse continue;
            const now = if (fork > timestamp_threshold) time else head;
            if (fork > now) return .{ .hash = hash, .next = fork };
            hash = self.sums[i + 1] orelse continue;
        }
        return .{ .hash = hash, .next = 0 };
    }

    pub fn check(self: *const IdFilter, remote: Id, head: u64, time: u64) bool {
        const current_id = self.currentId(head, time);
        if (std.meta.eql(current_id.hash, remote.hash)) {
            return !(remote.next > 0 and (head >= remote.next or (remote.next > timestamp_threshold and time >= remote.next)));
        }

        var current_fork_passed = false;
        for (0..self.sums.len) |i| {
            const sum = self.sums[i] orelse continue;

            current_fork_passed |= std.meta.eql(sum, current_id.hash);
            if (std.meta.eql(sum, remote.hash)) {
                if (current_fork_passed) return true;
                return self.nextForkAfter(i) == remote.next;
            }
        }
        return false;
    }

    fn nextForkAfter(self: *const IdFilter, sums_index: usize) u64 {
        var i = sums_index;
        while (i < self.schedule.inner.len) : (i += 1) {
            if (self.schedule.inner[i]) |fork| return fork;
        }
        return 0;
    }
};

test "calculate from genesis" {
    const genesis = [32]u8{ 0xd4, 0xe5, 0x67, 0x40, 0xf8, 0x76, 0xae, 0xf8, 0xc0, 0x10, 0xb8, 0x6a, 0x40, 0xd5, 0xf5, 0x67, 0x45, 0xa1, 0x18, 0xd0, 0x90, 0x6a, 0x34, 0xe6, 0x9a, 0xec, 0x8c, 0x0d, 0xb1, 0xcb, 0x8f, 0xa3 };
    const schedule = &mainnet_schedule;
    const filter = IdFilter.init(genesis, schedule);
    // Unsynced
    try std.testing.expectEqual(Id{ .hash = [4]u8{ 0xfc, 0x64, 0xec, 0x04 }, .next = 1150000 }, filter.currentId(0, 0));
    // Last Frontier block
    try std.testing.expectEqual(Id{ .hash = [4]u8{ 0xfc, 0x64, 0xec, 0x04 }, .next = 1150000 }, filter.currentId(1149999, 1149999));
    // First Homestead block
    try std.testing.expectEqual(Id{ .hash = [4]u8{ 0x97, 0xc2, 0xc3, 0x4c }, .next = 1920000 }, filter.currentId(1150000, 1150000));
    // Last Homestead block
    try std.testing.expectEqual(Id{ .hash = [4]u8{ 0x97, 0xc2, 0xc3, 0x4c }, .next = 1920000 }, filter.currentId(1919999, 1919999));
    // First DAO block
    try std.testing.expectEqual(Id{ .hash = [4]u8{ 0x91, 0xd1, 0xf9, 0x48 }, .next = 2463000 }, filter.currentId(1920000, 1920000));
    // Last DAO block
    try std.testing.expectEqual(Id{ .hash = [4]u8{ 0x91, 0xd1, 0xf9, 0x48 }, .next = 2463000 }, filter.currentId(2462999, 2462999));
    // First Tangerine Whistle block
    try std.testing.expectEqual(Id{ .hash = [4]u8{ 0x7a, 0x64, 0xda, 0x13 }, .next = 2675000 }, filter.currentId(2463000, 2463000));
    // Last Tangerine Whistle block
    try std.testing.expectEqual(Id{ .hash = [4]u8{ 0x7a, 0x64, 0xda, 0x13 }, .next = 2675000 }, filter.currentId(2674999, 2674999));
    // First Spurious Dragon block
    try std.testing.expectEqual(Id{ .hash = [4]u8{ 0x3e, 0xdd, 0x5b, 0x10 }, .next = 4370000 }, filter.currentId(2675000, 2675000));
    // Last Spurious Dragon block
    try std.testing.expectEqual(Id{ .hash = [4]u8{ 0x3e, 0xdd, 0x5b, 0x10 }, .next = 4370000 }, filter.currentId(4369999, 4369999));
    // First Byzantium block
    try std.testing.expectEqual(Id{ .hash = [4]u8{ 0xa0, 0x0b, 0xc3, 0x24 }, .next = 7280000 }, filter.currentId(4370000, 4370000));
    // Last Byzantium block
    try std.testing.expectEqual(Id{ .hash = [4]u8{ 0xa0, 0x0b, 0xc3, 0x24 }, .next = 7280000 }, filter.currentId(7279999, 7279999));
    // First and last Constantinople, first Petersburg block
    try std.testing.expectEqual(Id{ .hash = [4]u8{ 0x66, 0x8d, 0xb0, 0xaf }, .next = 9069000 }, filter.currentId(7280000, 7280000));
    // Last Petersburg block
    try std.testing.expectEqual(Id{ .hash = [4]u8{ 0x66, 0x8d, 0xb0, 0xaf }, .next = 9069000 }, filter.currentId(9068999, 9068999));
    // First Istanbul and first Muir Glacier block
    try std.testing.expectEqual(Id{ .hash = [4]u8{ 0x87, 0x9d, 0x6e, 0x30 }, .next = 9200000 }, filter.currentId(9069000, 9069000));
    // Last Istanbul and first Muir Glacier block
    try std.testing.expectEqual(Id{ .hash = [4]u8{ 0x87, 0x9d, 0x6e, 0x30 }, .next = 9200000 }, filter.currentId(9199999, 9199999));
    // First Muir Glacier block
    try std.testing.expectEqual(Id{ .hash = [4]u8{ 0xe0, 0x29, 0xe9, 0x91 }, .next = 12244000 }, filter.currentId(9200000, 9200000));
    // Last Muir Glacier block
    try std.testing.expectEqual(Id{ .hash = [4]u8{ 0xe0, 0x29, 0xe9, 0x91 }, .next = 12244000 }, filter.currentId(12243999, 12243999));
    // First Berlin block
    try std.testing.expectEqual(Id{ .hash = [4]u8{ 0x0e, 0xb4, 0x40, 0xf6 }, .next = 12965000 }, filter.currentId(12244000, 12244000));
    // Last Berlin block
    try std.testing.expectEqual(Id{ .hash = [4]u8{ 0x0e, 0xb4, 0x40, 0xf6 }, .next = 12965000 }, filter.currentId(12964999, 12964999));
    // First London block
    try std.testing.expectEqual(Id{ .hash = [4]u8{ 0xb7, 0x15, 0x07, 0x7d }, .next = 13773000 }, filter.currentId(12965000, 12965000));
    // Last London block
    try std.testing.expectEqual(Id{ .hash = [4]u8{ 0xb7, 0x15, 0x07, 0x7d }, .next = 13773000 }, filter.currentId(13772999, 13772999));
    // First Arrow Glacier block
    try std.testing.expectEqual(Id{ .hash = [4]u8{ 0x20, 0xc3, 0x27, 0xfc }, .next = 15050000 }, filter.currentId(13773000, 13773000));
    // Last Arrow Glacier block
    try std.testing.expectEqual(Id{ .hash = [4]u8{ 0x20, 0xc3, 0x27, 0xfc }, .next = 15050000 }, filter.currentId(15049999, 15049999));
    // First Gray Glacier block
    try std.testing.expectEqual(Id{ .hash = [4]u8{ 0xf0, 0xaf, 0xd0, 0xe3 }, .next = 1681338455 }, filter.currentId(15050000, 15050000));
    // Last Gray Glacier block
    try std.testing.expectEqual(Id{ .hash = [4]u8{ 0xf0, 0xaf, 0xd0, 0xe3 }, .next = 1681338455 }, filter.currentId(1681338454, 1681338454));
    // First Shanghai block
    try std.testing.expectEqual(Id{ .hash = [4]u8{ 0xdc, 0xe9, 0x6c, 0x2d }, .next = 1710338135 }, filter.currentId(1681338455, 1681338455));
    // Last Shanghai block
    try std.testing.expectEqual(Id{ .hash = [4]u8{ 0xdc, 0xe9, 0x6c, 0x2d }, .next = 1710338135 }, filter.currentId(1710338134, 1710338134));
    // First Cancun block
    try std.testing.expectEqual(Id{ .hash = [4]u8{ 0x9f, 0x3d, 0x22, 0x54 }, .next = 1746612311 }, filter.currentId(1710338135, 1710338135));
    // Last Cancun block
    try std.testing.expectEqual(Id{ .hash = [4]u8{ 0x9f, 0x3d, 0x22, 0x54 }, .next = 1746612311 }, filter.currentId(1746022486, 1746022486));
    // First Prague block
    try std.testing.expectEqual(Id{ .hash = [4]u8{ 0xc3, 0x76, 0xcf, 0x8b }, .next = 1764798551 }, filter.currentId(1746612311, 1746612311));
    // Last Prague block
    try std.testing.expectEqual(Id{ .hash = [4]u8{ 0xc3, 0x76, 0xcf, 0x8b }, .next = 1764798551 }, filter.currentId(1764798550, 1764798550));
    // First Osaka block
    try std.testing.expectEqual(Id{ .hash = [4]u8{ 0x51, 0x67, 0xe2, 0xa6 }, .next = 1765290071 }, filter.currentId(1764798551, 1764798551));
    // Last Osaka block
    try std.testing.expectEqual(Id{ .hash = [4]u8{ 0x51, 0x67, 0xe2, 0xa6 }, .next = 1765290071 }, filter.currentId(1765290070, 1765290070));
    // First BPO1 block
    try std.testing.expectEqual(Id{ .hash = [4]u8{ 0xcb, 0xa2, 0xa1, 0xc0 }, .next = 1767747671 }, filter.currentId(1765290071, 1765290071));
    // Last BPO1 block
    try std.testing.expectEqual(Id{ .hash = [4]u8{ 0xcb, 0xa2, 0xa1, 0xc0 }, .next = 1767747671 }, filter.currentId(1767747670, 1767747670));
    // First BPO2 block
    try std.testing.expectEqual(Id{ .hash = [4]u8{ 0x07, 0xc9, 0x46, 0x2e }, .next = 0 }, filter.currentId(1767747671, 1767747671));
    // Future BPO2 block
    try std.testing.expectEqual(Id{ .hash = [4]u8{ 0x07, 0xc9, 0x46, 0x2e }, .next = 0 }, filter.currentId(2000000000, 2000000000));
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

fn checksumBytes(hash: u32) [4]u8 {
    var out: [4]u8 = undefined;
    std.mem.writeInt(u32, &out, hash, .big);
    return out;
}

fn checksumUpdateBytes(hash: u32, fork: u64) [4]u8 {
    var crc: std.hash.Crc32 = .{ .crc = hash ^ 0xffffffff };
    var blob: [8]u8 = undefined;
    std.mem.writeInt(u64, &blob, fork, .big);
    crc.update(&blob);
    return checksumBytes(crc.final());
}

test "validation" {
    const legacy_mainnet_schedule = Schedule.init(.{
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
    });
    const genesis = [32]u8{ 0xd4, 0xe5, 0x67, 0x40, 0xf8, 0x76, 0xae, 0xf8, 0xc0, 0x10, 0xb8, 0x6a, 0x40, 0xd5, 0xf5, 0x67, 0x45, 0xa1, 0x18, 0xd0, 0x90, 0x6a, 0x34, 0xe6, 0x9a, 0xec, 0x8c, 0x0d, 0xb1, 0xcb, 0x8f, 0xa3 };
    const max_u64 = std.math.maxInt(u64);

    const Case = struct {
        head: u64,
        time: u64,
        hash: [4]u8,
        next: u64,
        want: bool,
    };

    // Block based tests (legacy config: mainnet with no timestamp forks).
    const legacy_filter = IdFilter.init(genesis, &legacy_mainnet_schedule);
    const legacy_cases = [_]Case{
        // Local is mainnet Gray Glacier, remote announces the same. No future fork is announced.
        .{ .head = 15050000, .time = 0, .hash = checksumBytes(0xf0afd0e3), .next = 0, .want = true },
        // Local is mainnet Gray Glacier, remote announces the same. Remote also announces a next fork
        // at block 0xffffffff, but that is uncertain.
        .{ .head = 15050000, .time = 0, .hash = checksumBytes(0xf0afd0e3), .next = max_u64, .want = true },
        // Local is mainnet currently in Byzantium only (so it's aware of Petersburg), remote announces
        // also Byzantium, but it's not yet aware of Petersburg. We don't know if Petersburg passed yet.
        .{ .head = 7279999, .time = 0, .hash = checksumBytes(0xa00bc324), .next = 0, .want = true },
        // Local is mainnet currently in Byzantium only, remote announces also Byzantium and is aware
        // of Petersburg. We don't know if Petersburg passed yet (will pass) or not.
        .{ .head = 7279999, .time = 0, .hash = checksumBytes(0xa00bc324), .next = 7280000, .want = true },
        // Local is mainnet currently in Byzantium only, remote announces also Byzantium, and is also
        // aware of some random fork. Neither fork passed at either node, but still connect for now.
        .{ .head = 7279999, .time = 0, .hash = checksumBytes(0xa00bc324), .next = max_u64, .want = true },
        // Local is mainnet exactly on Petersburg, remote announces Byzantium + knowledge about
        // Petersburg. Remote is simply out of sync, accept.
        .{ .head = 7280000, .time = 0, .hash = checksumBytes(0xa00bc324), .next = 7280000, .want = true },
        // Local is mainnet Petersburg, remote announces Byzantium + knowledge about Petersburg. Remote
        // is simply out of sync, accept.
        .{ .head = 7987396, .time = 0, .hash = checksumBytes(0xa00bc324), .next = 7280000, .want = true },
        // Local is mainnet Petersburg, remote announces Spurious + knowledge about Byzantium. Remote
        // is definitely out of sync. It may or may not need the Petersburg update, we don't know yet.
        .{ .head = 7987396, .time = 0, .hash = checksumBytes(0x3edd5b10), .next = 4370000, .want = true },
        // Local is mainnet Byzantium, remote announces Petersburg. Local is out of sync, accept.
        .{ .head = 7279999, .time = 0, .hash = checksumBytes(0x668db0af), .next = 0, .want = true },
        // Local is mainnet Spurious, remote announces Byzantium, but is not aware of Petersburg. Local
        // out of sync. Local also knows about a future fork, but that is uncertain yet.
        .{ .head = 4369999, .time = 0, .hash = checksumBytes(0xa00bc324), .next = 0, .want = true },
        // Local is mainnet Petersburg. remote announces Byzantium but is not aware of further forks.
        // Remote needs software update. (go: ErrRemoteStale)
        .{ .head = 7987396, .time = 0, .hash = checksumBytes(0xa00bc324), .next = 0, .want = false },
        // Local is mainnet Petersburg, and isn't aware of more forks. Remote announces Petersburg +
        // 0xffffffff. Local needs software update, reject. (go: ErrLocalIncompatibleOrStale)
        .{ .head = 7987396, .time = 0, .hash = checksumBytes(0x5cddc0e1), .next = 0, .want = false },
        // Local is mainnet Byzantium, and is aware of Petersburg. Remote announces Petersburg +
        // 0xffffffff. Local needs software update, reject.
        .{ .head = 7279999, .time = 0, .hash = checksumBytes(0x5cddc0e1), .next = 0, .want = false },
        // Local is mainnet Petersburg, remote is Rinkeby Petersburg.
        .{ .head = 7987396, .time = 0, .hash = checksumBytes(0xafec6b27), .next = 0, .want = false },
        // Local is mainnet Gray Glacier, far in the future. Remote announces Gopherium (non existing
        // fork) at some future block 88888888, for itself, but past block for local. Local is
        // incompatible.
        .{ .head = 88888888, .time = 0, .hash = checksumBytes(0xf0afd0e3), .next = 88888888, .want = false },
        // Local is mainnet Byzantium. Remote is also in Byzantium, but announces Gopherium (non
        // existing fork) at block 7279999, before Petersburg. Local is incompatible.
        .{ .head = 7279999, .time = 0, .hash = checksumBytes(0xa00bc324), .next = 7279999, .want = false },
    };
    for (legacy_cases) |tc| {
        errdefer std.debug.print("legacy case {} failed\n", .{tc});
        const have = legacy_filter.check(.{ .hash = tc.hash, .next = tc.next }, tc.head, tc.time);
        try std.testing.expectEqual(tc.want, have);
    }

    // Block to timestamp transition tests, and timestamp based tests (mainnet config).
    const mainnet_filter = IdFilter.init(genesis, &mainnet_schedule);
    const mainnet_cases = [_]Case{
        // Local is mainnet currently in Gray Glacier only (so it's aware of Shanghai), remote announces
        // also Gray Glacier, but it's not yet aware of Shanghai. We don't know if Shanghai passed yet.
        .{ .head = 15050000, .time = 0, .hash = checksumBytes(0xf0afd0e3), .next = 0, .want = true },
        // Local is mainnet currently in Gray Glacier only, remote announces also Gray Glacier, and is
        // also aware of Shanghai. We don't know if Shanghai passed yet (will pass) or not.
        .{ .head = 15050000, .time = 0, .hash = checksumBytes(0xf0afd0e3), .next = 1681338455, .want = true },
        // Local is mainnet currently in Gray Glacier only, remote announces also Gray Glacier, and is
        // also aware of some random fork. Neither fork passed at either node, still connect for now.
        .{ .head = 15050000, .time = 0, .hash = checksumBytes(0xf0afd0e3), .next = max_u64, .want = true },
        // Local is mainnet exactly on Shanghai, remote announces Gray Glacier + knowledge about
        // Shanghai. Remote is simply out of sync, accept.
        .{ .head = 20000000, .time = 1681338455, .hash = checksumBytes(0xf0afd0e3), .next = 1681338455, .want = true },
        // Local is mainnet Shanghai, remote announces Gray Glacier + knowledge about Shanghai. Remote
        // is simply out of sync, accept.
        .{ .head = 20123456, .time = 1681338456, .hash = checksumBytes(0xf0afd0e3), .next = 1681338455, .want = true },
        // Local is mainnet Shanghai, remote announces Arrow Glacier + knowledge about Gray Glacier.
        // Remote is definitely out of sync. It may or may not need the Shanghai update, unknown yet.
        .{ .head = 20000000, .time = 1681338455, .hash = checksumBytes(0x20c327fc), .next = 15050000, .want = true },
        // Local is mainnet Gray Glacier, remote announces Shanghai. Local is out of sync, accept.
        .{ .head = 15050000, .time = 0, .hash = checksumBytes(0xdce96c2d), .next = 0, .want = true },
        // Local is mainnet Arrow Glacier, remote announces Gray Glacier, but is not aware of Shanghai.
        // Local out of sync. Local also knows about a future fork, but that is uncertain yet.
        .{ .head = 13773000, .time = 0, .hash = checksumBytes(0xf0afd0e3), .next = 0, .want = true },
        // Local is mainnet Shanghai. remote announces Gray Glacier but is not aware of further forks.
        // Remote needs software update. (go: ErrRemoteStale)
        .{ .head = 20000000, .time = 1681338455, .hash = checksumBytes(0xf0afd0e3), .next = 0, .want = false },
        // Local is mainnet Gray Glacier, and isn't aware of more forks. Remote announces Gray Glacier +
        // 0xffffffff. Local needs software update, reject.
        .{ .head = 15050000, .time = 0, .hash = checksumUpdateBytes(0xf0afd0e3, max_u64), .next = 0, .want = false },
        // Local is mainnet Gray Glacier, and is aware of Shanghai. Remote announces Shanghai +
        // 0xffffffff. Local needs software update, reject.
        .{ .head = 15050000, .time = 0, .hash = checksumUpdateBytes(0xdce96c2d, max_u64), .next = 0, .want = false },
        // Local is mainnet Gray Glacier, far in the future. Remote announces Gopherium (non existing
        // fork) at some future timestamp 8888888888, for itself, but past block for local. Local is
        // incompatible.
        .{ .head = 888888888, .time = 1660000000, .hash = checksumBytes(0xf0afd0e3), .next = 1660000000, .want = false },
        // Local is mainnet Gray Glacier. Remote is also in Gray Glacier, but announces Gopherium (non
        // existing fork) at block 7279999, before Shanghai. Local is incompatible.
        .{ .head = 19999999, .time = 1667999999, .hash = checksumBytes(0xf0afd0e3), .next = 1667999999, .want = false },

        // Local is mainnet Shanghai, remote announces the same. No future fork is announced.
        .{ .head = 20000000, .time = 1681338455, .hash = checksumBytes(0xdce96c2d), .next = 0, .want = true },
        // Local is mainnet Shanghai, remote announces the same. Remote also announces a next fork at
        // time 0xffffffff, but that is uncertain.
        .{ .head = 20000000, .time = 1681338455, .hash = checksumBytes(0xdce96c2d), .next = max_u64, .want = true },
        // Local is mainnet currently in Shanghai only (so it's aware of Cancun), remote announces also
        // Shanghai, but it's not yet aware of Cancun. We don't know if Cancun passed yet or not.
        .{ .head = 20000000, .time = 1668000000, .hash = checksumBytes(0xdce96c2d), .next = 0, .want = true },
        // Local is mainnet currently in Shanghai only, remote announces also Shanghai, and is also
        // aware of Cancun. We don't know if Cancun passed yet (will pass) or not.
        .{ .head = 20000000, .time = 1668000000, .hash = checksumBytes(0xdce96c2d), .next = 1710338135, .want = true },
        // Local is mainnet currently in Shanghai only, remote announces also Shanghai, and is also
        // aware of some random fork. Neither fork passed at either node, still connect for now.
        .{ .head = 20000000, .time = 1668000000, .hash = checksumBytes(0xdce96c2d), .next = max_u64, .want = true },
        // Local is mainnet exactly on Cancun, remote announces Shanghai + knowledge about Cancun.
        // Remote is simply out of sync, accept.
        .{ .head = 21000000, .time = 1710338135, .hash = checksumBytes(0xdce96c2d), .next = 1710338135, .want = true },
        // Local is mainnet Cancun, remote announces Shanghai + knowledge about Cancun. Remote is
        // simply out of sync, accept.
        .{ .head = 21123456, .time = 1710338136, .hash = checksumBytes(0xdce96c2d), .next = 1710338135, .want = true },
        // Local is mainnet Prague, remote announces Shanghai + knowledge about Cancun. Remote is
        // definitely out of sync. It may or may not need the Prague update, we don't know yet.
        .{ .head = 0, .time = 0, .hash = checksumBytes(0x3edd5b10), .next = 1710338135, .want = true },
        // Local is mainnet Shanghai, remote announces Cancun. Local is out of sync, accept.
        .{ .head = 21000000, .time = 1700000000, .hash = checksumBytes(0x9f3d2254), .next = 0, .want = true },
        // Local is mainnet Shanghai, remote announces Cancun, but is not aware of Prague. Local out of
        // sync. Local also knows about a future fork, but that is uncertain yet.
        .{ .head = 21000000, .time = 1678000000, .hash = checksumBytes(0xc376cf8b), .next = 0, .want = true },
        // Local is mainnet Cancun. remote announces Shanghai but is not aware of further forks. Remote
        // needs software update. (go: ErrRemoteStale)
        .{ .head = 21000000, .time = 1710338135, .hash = checksumBytes(0xdce96c2d), .next = 0, .want = false },
        // Local is mainnet Shanghai, and isn't aware of more forks. Remote announces Shanghai +
        // 0xffffffff. Local needs software update, reject.
        .{ .head = 20000000, .time = 1681338455, .hash = checksumUpdateBytes(0xdce96c2d, max_u64), .next = 0, .want = false },
        // Local is mainnet Shanghai, and is aware of Cancun. Remote announces Cancun + 0xffffffff.
        // Local needs software update, reject.
        .{ .head = 20000000, .time = 1668000000, .hash = checksumUpdateBytes(0x9f3d2254, max_u64), .next = 0, .want = false },
        // Local is mainnet Shanghai, remote is random Shanghai.
        .{ .head = 20000000, .time = 1681338455, .hash = checksumBytes(0x12345678), .next = 0, .want = false },
        // Local is mainnet BPO2, far in the future. Remote announces Gopherium (non existing fork) at
        // some future timestamp 8888888888, for itself, but past block for local. Local is incompatible.
        .{ .head = 88888888, .time = 8888888888, .hash = checksumBytes(0x07c9462e), .next = 8888888888, .want = false },
        // Local is mainnet Shanghai. Remote is also in Shanghai, but announces Gopherium (non existing
        // fork) at timestamp 1668000000, before Cancun. Local is incompatible.
        .{ .head = 20999999, .time = 1699999999, .hash = checksumBytes(0x71147644), .next = 1700000000, .want = false },
    };
    for (mainnet_cases, 0..) |tc, i| {
        errdefer std.debug.print("mainnet case {d} failed\n", .{i});
        const have = mainnet_filter.check(.{ .hash = tc.hash, .next = tc.next }, tc.head, tc.time);
        try std.testing.expectEqual(tc.want, have);
    }
}
