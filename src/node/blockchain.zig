const std = @import("std");
const types = @import("../types.zig");
const forks = @import("../forks.zig");
const rlp = @import("rlp");
const FileStorage = @import("../db/file.zig").Storage;

pub const Config = struct {
    chain_id: u64,
    genesis_header: types.BlockHeader,
    fork_schedule: forks.Schedule,
};

pub const Blockchain = struct {
    const Self = @This();

    cfg: Config,

    io: std.Io,
    allocator: std.mem.Allocator,
    file_storage: *FileStorage,

    pub fn init(io: std.Io, allocator: std.mem.Allocator, cfg: Config, file_storage: *FileStorage) !Self {
        var bc = Self{
            .file_storage = file_storage,
            .cfg = cfg,
            .io = io,
            .allocator = allocator,
        };
        if (file_storage.ranges[@intFromEnum(FileStorage.Table.headers)] == null) {
            try bc.appendHeader(&cfg.genesis_header);
        }
        return bc;
    }

    pub fn chainId(self: *Self) u64 {
        return self.cfg.chain_id;
    }

    pub fn genesisHash(self: *Self) [32]u8 {
        return self.cfg.genesis_header.hash();
    }

    pub fn head(self: *Self) !struct { number: u64, hash: [32]u8 } {
        const header = try self.headHeader();
        return .{ .number = header.number, .hash = header.hash() };
    }

    pub fn headHeader(self: *Self) !types.BlockHeader {
        const range = self.file_storage.ranges[@intFromEnum(FileStorage.Table.headers)];
        return (try self.readHeader(range.?.head)).?;
    }

    pub fn readHeader(self: *Self, number: u64) !?types.BlockHeader {
        if (try self.file_storage.get(self.io, self.allocator, .headers, number)) |header_rlp| {
            defer self.allocator.free(header_rlp);
            var header: types.BlockHeader = undefined;
            _ = try rlp.deserialize(types.BlockHeader, self.allocator, header_rlp, &header);
            return header;
        }
        return null;
    }

    pub fn appendHeader(self: *Self, header: *const types.BlockHeader) !void {
        var list = std.array_list.Managed(u8).init(self.allocator);
        defer list.deinit();
        _ = try rlp.serialize(types.BlockHeader, self.allocator, header.*, &list);

        try self.file_storage.put(self.io, self.allocator, .headers, header.number, list.items);
    }
};

pub const glamsterdam_devnet8_config: Config = .{
    .chain_id = 7091047534,
    .genesis_header = .{
        .parent_hash = .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
        .ommers_hash = .{ 29, 204, 77, 232, 222, 199, 93, 122, 171, 133, 181, 103, 182, 204, 212, 26, 211, 18, 69, 27, 148, 138, 116, 19, 240, 161, 66, 253, 64, 212, 147, 71 },
        .beneficiary = .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
        .state_root = .{ 154, 82, 122, 238, 93, 15, 107, 12, 115, 178, 64, 231, 124, 19, 76, 174, 31, 212, 124, 234, 169, 13, 178, 35, 237, 213, 152, 134, 110, 38, 156, 71 },
        .transactions_root = .{ 86, 232, 31, 23, 27, 204, 85, 166, 255, 131, 69, 230, 146, 192, 248, 110, 91, 72, 224, 27, 153, 108, 173, 192, 1, 98, 47, 181, 227, 99, 180, 33 },
        .receipts_root = .{ 86, 232, 31, 23, 27, 204, 85, 166, 255, 131, 69, 230, 146, 192, 248, 110, 91, 72, 224, 27, 153, 108, 173, 192, 1, 98, 47, 181, 227, 99, 180, 33 },
        .logs_bloom = .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
        .difficulty = 0,
        .number = 0,
        .gas_limit = 60000000,
        .gas_used = 0,
        .timestamp = 1786622400,
        .extra_data = .{ .buf = .{ 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170 }, .len = 0 },
        .mix_hash = .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
        .nonce = .{ 0, 0, 0, 0, 0, 0, 18, 52 },
        .base_fee_per_gas = 1000000000,
        .withdrawals_root = .{ 86, 232, 31, 23, 27, 204, 85, 166, 255, 131, 69, 230, 146, 192, 248, 110, 91, 72, 224, 27, 153, 108, 173, 192, 1, 98, 47, 181, 227, 99, 180, 33 },
        .blob_gas_used = 0,
        .excess_blob_gas = 0,
        .parent_beacon_block_root = .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
        .requests_hash = .{ 227, 176, 196, 66, 152, 252, 28, 20, 154, 251, 244, 200, 153, 111, 185, 36, 39, 174, 65, 228, 100, 155, 147, 76, 164, 149, 153, 27, 120, 82, 184, 85 },
        .block_access_list_hash = null,
        .slot_number = null,
    },
    .fork_schedule = forks.glamsterdam_devnet8_schedule,
};
