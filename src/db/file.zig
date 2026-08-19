const std = @import("std");
const cache = @import("cache");
const snappy = @import("snappy").raw;

var max_file_size: u32 = 3 * 1024 * 1024 * 1024;
const tail_size = @sizeOf(u64);

const IndexEntry = struct {
    const size = 6;

    file_no: u16,
    offset: u32,

    pub fn decode(b: [6]u8) IndexEntry {
        return .{ .file_no = std.mem.readInt(u16, b[0..2], .big), .offset = std.mem.readInt(u32, b[2..6], .big) };
    }

    pub fn encode(self: *const IndexEntry) [6]u8 {
        var b: [6]u8 = undefined;
        std.mem.writeInt(u16, b[0..2], self.file_no, .big);
        std.mem.writeInt(u32, b[2..6], self.offset, .big);
        return b;
    }
};

const PooledFile = struct {
    io: std.Io,
    file: std.Io.File,

    pub fn removedFromCache(self: PooledFile, _: std.mem.Allocator) void {
        self.file.close(self.io);
    }
};

const FileOpener = struct {
    io: std.Io,
    datadir: std.Io.Dir,

    fn open(self: FileOpener, file_name: []const u8) anyerror!?PooledFile {
        const file = try self.datadir.createFile(self.io, file_name, .{
            .read = true,
            .truncate = false,
        });
        return .{ .io = self.io, .file = file };
    }
};

pub const Storage = struct {
    const Self = @This();
    pub const Table = enum(u8) {
        headers = 0,
        bodies = 1,
        receipts = 2,
        bals = 3,
    };

    datadir: std.Io.Dir,

    next_indexes: [std.enums.values(Table).len]IndexEntry,
    ranges: [std.enums.values(Table).len]?struct { tail: u64, head: u64 },
    file_pool: cache.Cache(PooledFile),

    lock: std.Io.RwLock,

    pub fn init(io: std.Io, allocator: std.mem.Allocator, path: []const u8) !Self {
        const datadir = try std.Io.Dir.openDirAbsolute(io, path, .{});
        var s = Self{
            .datadir = datadir,
            .next_indexes = undefined,
            .ranges = @splat(null),
            .file_pool = try .init(io, allocator, .{ .max_size = 64 }),
            .lock = .init,
        };
        errdefer s.deinit(io, allocator) catch unreachable;

        try s.initRanges(io);
        const tables = std.enums.values(Table);
        for (tables) |table| {
            s.next_indexes[@intFromEnum(table)] = try s.initialNextIndex(io, table);
        }

        return s;
    }

    pub fn deinit(self: *Self, io: std.Io, _: std.mem.Allocator) !void {
        defer self.file_pool.deinit();
        for (self.ranges, 0..) |range, index| {
            if (range) |r| {
                const table: Table = @enumFromInt(index);
                const index_file = try self.openIndexFile(io, table);
                defer index_file.release();

                var buf: [tail_size]u8 = @splat(0);
                std.mem.writeInt(u64, &buf, r.tail, .big);
                try index_file.value.file.writePositionalAll(io, &buf, 0);
            }
        }
    }

    fn initRanges(self: *Self, io: std.Io) !void {
        for (&self.ranges, 0..) |*range, index| {
            const table: Table = @enumFromInt(index);
            const index_file = try self.openIndexFile(io, table);
            defer index_file.release();
            const index_file_len = try index_file.value.file.length(io);

            var buf: [tail_size]u8 = @splat(0);
            if (index_file_len == 0) {
                try index_file.value.file.writePositionalAll(io, &buf, 0);
            } else if (index_file_len > tail_size) {
                const entry_bytes = index_file_len - tail_size;
                if (entry_bytes % IndexEntry.size != 0) return error.CorruptedIndexFile;

                const size = try index_file.value.file.readPositionalAll(io, &buf, 0);
                if (size != tail_size) return error.RangeReadError;
                const tail = std.mem.readInt(u64, buf[0..tail_size], .big);

                const entry_count = entry_bytes / IndexEntry.size;
                if (entry_count == 0) continue;

                range.* = .{ .tail = tail, .head = tail + entry_count - 1 };
            } else if (index_file_len < tail_size) {
                return error.CorruptedIndexFile;
            }
        }
    }

    fn initialNextIndex(self: *Self, io: std.Io, table: Table) !IndexEntry {
        const index_file = try self.openIndexFile(io, table);
        defer index_file.release();

        const index_file_size = try index_file.value.file.length(io);

        if (index_file_size >= tail_size + IndexEntry.size) {
            var last_entry_bytes: [6]u8 = undefined;

            const read = try index_file.value.file.readPositionalAll(io, &last_entry_bytes, index_file_size - IndexEntry.size);
            std.debug.assert(read == IndexEntry.size);

            const entry = IndexEntry.decode(last_entry_bytes);
            const data_file = try self.openDataFile(io, table, entry.file_no);
            defer data_file.release();

            const data_file_len = try data_file.value.file.length(io);
            return .{ .file_no = entry.file_no, .offset = @intCast(data_file_len) };
        }
        return .{ .file_no = 0, .offset = 0 };
    }

    pub fn openFile(self: *Self, io: std.Io, file_name: []const u8) !*cache.Entry(PooledFile) {
        const opener = FileOpener{ .io = io, .datadir = self.datadir };
        return try self.file_pool.fetch(FileOpener, file_name, FileOpener.open, opener, .{}) orelse return error.OpenFailed;
    }

    pub fn openIndexFile(self: *Self, io: std.Io, table: Table) !*cache.Entry(PooledFile) {
        const table_name = @tagName(table);

        var buf: [1024]u8 = undefined;
        const index_file = try std.fmt.bufPrint(&buf, "{s}-index.dat", .{table_name});
        return self.openFile(io, index_file);
    }

    pub fn openDataFile(self: *Self, io: std.Io, table: Table, file_no: u16) !*cache.Entry(PooledFile) {
        const table_name = @tagName(table);

        var buf: [1024]u8 = undefined;
        const index_path = try std.fmt.bufPrint(&buf, "{s}-{d:0>5}.dat", .{ table_name, file_no });
        return self.openFile(io, index_path);
    }

    pub fn put(self: *Self, io: std.Io, allocator: std.mem.Allocator, table: Table, number: u64, data: []const u8) !void {
        if (data.len == 0) return error.EmptyData;

        self.lock.lockUncancelable(io);
        defer self.lock.unlock(io);

        const prev_range = self.ranges[@intFromEnum(table)];
        if (prev_range) |range| {
            if (range.head + 1 != number) return error.OutOfOrderPut;
        } else {
            self.ranges[@intFromEnum(table)] = .{ .tail = number, .head = number };
        }
        self.ranges[@intFromEnum(table)].?.head = number;
        errdefer self.ranges[@intFromEnum(table)] = prev_range;

        const max_size = snappy.maxCompressedLength(data.len);
        const compressed_buf = try allocator.alloc(u8, max_size);
        defer allocator.free(compressed_buf);
        const compressed_len = try snappy.compress(data, compressed_buf);

        const index = self.advanceIndex(table, compressed_len);
        errdefer self.next_indexes[@intFromEnum(table)] = index;

        const index_file = try self.openIndexFile(io, table);
        defer index_file.release();

        const index_file_length = try index_file.value.file.length(io);
        errdefer index_file.value.file.setLength(io, index_file_length) catch unreachable;
        try index_file.value.file.writePositionalAll(io, &index.encode(), index_file_length);

        const data_file = try self.openDataFile(io, table, index.file_no);
        defer data_file.release();

        const data_file_length = try data_file.value.file.length(io);
        try data_file.value.file.writePositionalAll(io, compressed_buf[0..compressed_len], data_file_length);
    }

    pub fn advanceIndex(self: *Self, table: Table, size: usize) IndexEntry {
        var index = self.next_indexes[@intFromEnum(table)];
        if (index.offset + size > max_file_size) {
            index = .{
                .file_no = index.file_no + 1,
                .offset = 0,
            };
        }

        self.next_indexes[@intFromEnum(table)] = .{
            .file_no = index.file_no,
            .offset = @intCast(index.offset + size),
        };
        return index;
    }

    pub fn get(self: *Self, io: std.Io, allocator: std.mem.Allocator, table: Table, number: u64) !?[]const u8 {
        self.lock.lockSharedUncancelable(io);
        defer self.lock.unlockShared(io);

        var offset = number;
        if (self.ranges[@intFromEnum(table)]) |range| {
            if (range.tail > number or range.head < number) return null;
            offset -= range.tail;
        } else {
            return null;
        }

        const index_offset = (offset * IndexEntry.size) + tail_size;

        const index_file = try self.openIndexFile(io, table);
        defer index_file.release();

        var index_buf: [2 * IndexEntry.size]u8 = undefined;
        var read = try index_file.value.file.readPositionalAll(io, &index_buf, index_offset);

        var target_index: IndexEntry = undefined;
        var next_index: ?IndexEntry = null;
        if (read == IndexEntry.size) {
            target_index = IndexEntry.decode(index_buf[0..IndexEntry.size].*);
        } else if (read == 2 * IndexEntry.size) {
            target_index = IndexEntry.decode(index_buf[0..IndexEntry.size].*);
            next_index = IndexEntry.decode(index_buf[IndexEntry.size .. 2 * IndexEntry.size].*);
        } else return error.IndexReadError;

        const data_file = try self.openDataFile(io, table, target_index.file_no);
        defer data_file.release();

        const bounded = if (next_index) |index| index.file_no == target_index.file_no else false;
        const len = if (bounded)
            next_index.?.offset - target_index.offset
        else
            try data_file.value.file.length(io) - target_index.offset;

        const buf = try allocator.alloc(u8, len);
        defer allocator.free(buf);
        read = try data_file.value.file.readPositionalAll(io, buf, target_index.offset);
        if (read != len) return error.ReadError;

        const decompressed_len = try snappy.uncompressedLength(buf);
        const decompressed_buf = try allocator.alloc(u8, decompressed_len);
        errdefer allocator.free(decompressed_buf);
        _ = try snappy.uncompress(buf, decompressed_buf);

        return decompressed_buf;
    }
};

test "readonly datadir" {
    var tmpdir = std.testing.tmpDir(.{});
    var perm: std.Io.Dir.Permissions = .default_dir;
    try tmpdir.dir.createDir(std.testing.io, "rodir", perm.setReadOnly(true));
    defer tmpdir.cleanup();

    var path: [1024]u8 = undefined;
    const size = try tmpdir.dir.realPathFile(std.testing.io, "rodir", &path);
    try std.testing.expectError(error.AccessDenied, Storage.init(std.testing.io, std.testing.allocator, path[0..size]));
}

test "empty dir" {
    var tmpdir = std.testing.tmpDir(.{});
    try tmpdir.dir.createDir(std.testing.io, "datadir", .default_dir);
    defer tmpdir.cleanup();

    var path: [1024]u8 = undefined;
    const size = try tmpdir.dir.realPathFile(std.testing.io, "datadir", &path);
    const data = [_]u8{ 38, 95 };

    {
        var storage = try Storage.init(std.testing.io, std.testing.allocator, path[0..size]);
        defer storage.deinit(std.testing.io, std.testing.allocator) catch unreachable;
        for (storage.ranges) |range| {
            try std.testing.expect(range == null);
        }

        for (storage.next_indexes) |ni| {
            try std.testing.expect(ni.file_no == 0 and ni.offset == 0);
        }

        try storage.put(std.testing.io, std.testing.allocator, .bals, 44, &data);
        const read = try storage.get(std.testing.io, std.testing.allocator, .bals, 44);
        defer std.testing.allocator.free(read.?);
        try std.testing.expectEqualSlices(u8, &data, read.?);
    }

    var second_storage = try Storage.init(std.testing.io, std.testing.allocator, path[0..size]);
    defer second_storage.deinit(std.testing.io, std.testing.allocator) catch unreachable;
    try std.testing.expect(second_storage.ranges[@intFromEnum(Storage.Table.bals)].?.head == 44);
    try std.testing.expect(second_storage.ranges[@intFromEnum(Storage.Table.bals)].?.tail == 44);

    const read = try second_storage.get(std.testing.io, std.testing.allocator, .bals, 44);
    defer std.testing.allocator.free(read.?);
    try std.testing.expectEqualSlices(u8, &data, read.?);
}

test "put after reopen appends" {
    var tmpdir = std.testing.tmpDir(.{});
    try tmpdir.dir.createDir(std.testing.io, "datadir", .default_dir);
    defer tmpdir.cleanup();

    var path: [1024]u8 = undefined;
    const size = try tmpdir.dir.realPathFile(std.testing.io, "datadir", &path);
    const first = [_]u8{ 38, 95 };
    const second = [_]u8{ 1, 2, 3, 4, 5 };

    {
        var storage = try Storage.init(std.testing.io, std.testing.allocator, path[0..size]);
        defer storage.deinit(std.testing.io, std.testing.allocator) catch unreachable;
        try storage.put(std.testing.io, std.testing.allocator, .bals, 44, &first);
    }

    var storage = try Storage.init(std.testing.io, std.testing.allocator, path[0..size]);
    defer storage.deinit(std.testing.io, std.testing.allocator) catch unreachable;

    const next_index = storage.next_indexes[@intFromEnum(Storage.Table.bals)];
    try std.testing.expect(next_index.file_no == 0 and next_index.offset > 0);

    try storage.put(std.testing.io, std.testing.allocator, .bals, 45, &second);

    const read_first = try storage.get(std.testing.io, std.testing.allocator, .bals, 44);
    defer std.testing.allocator.free(read_first.?);
    try std.testing.expectEqualSlices(u8, &first, read_first.?);

    const read_second = try storage.get(std.testing.io, std.testing.allocator, .bals, 45);
    defer std.testing.allocator.free(read_second.?);
    try std.testing.expectEqualSlices(u8, &second, read_second.?);
}

test "data file rollover" {
    var tmpdir = std.testing.tmpDir(.{});
    try tmpdir.dir.createDir(std.testing.io, "datadir", .default_dir);
    defer tmpdir.cleanup();

    var path: [1024]u8 = undefined;
    const size = try tmpdir.dir.realPathFile(std.testing.io, "datadir", &path);

    var storage = try Storage.init(std.testing.io, std.testing.allocator, path[0..size]);
    defer storage.deinit(std.testing.io, std.testing.allocator) catch unreachable;

    const records = [_][8]u8{
        .{ 1, 2, 3, 4, 5, 6, 7, 8 },
        .{ 9, 10, 11, 12, 13, 14, 15, 16 },
        .{ 17, 18, 19, 20, 21, 22, 23, 24 },
    };

    try storage.put(std.testing.io, std.testing.allocator, .bals, 0, &records[0]);
    const record_len = storage.next_indexes[@intFromEnum(Storage.Table.bals)].offset;
    try std.testing.expect(record_len > 0);

    const restore_max_file_size = max_file_size;
    max_file_size = record_len * 2;
    defer max_file_size = restore_max_file_size;

    try storage.put(std.testing.io, std.testing.allocator, .bals, 1, &records[1]);
    try storage.put(std.testing.io, std.testing.allocator, .bals, 2, &records[2]);

    const next_index = storage.next_indexes[@intFromEnum(Storage.Table.bals)];
    try std.testing.expect(next_index.file_no == 1 and next_index.offset == record_len);

    const first_file = try storage.openDataFile(std.testing.io, .bals, 0);
    defer first_file.release();
    try std.testing.expectEqual(@as(u64, record_len) * 2, try first_file.value.file.length(std.testing.io));

    const second_file = try storage.openDataFile(std.testing.io, .bals, 1);
    defer second_file.release();
    try std.testing.expectEqual(@as(u64, record_len), try second_file.value.file.length(std.testing.io));

    for (records, 0..) |record, number| {
        const read = try storage.get(std.testing.io, std.testing.allocator, .bals, number);
        defer std.testing.allocator.free(read.?);
        try std.testing.expectEqualSlices(u8, &record, read.?);
    }
}
