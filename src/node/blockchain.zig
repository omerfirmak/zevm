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

pub const mainnet_config: Config = .{
    .chain_id = 1,
    .genesis_header = .{
        .parent_hash = .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
        .ommers_hash = .{ 29, 204, 77, 232, 222, 199, 93, 122, 171, 133, 181, 103, 182, 204, 212, 26, 211, 18, 69, 27, 148, 138, 116, 19, 240, 161, 66, 253, 64, 212, 147, 71 },
        .beneficiary = .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
        .state_root = .{ 215, 248, 151, 79, 181, 172, 120, 217, 172, 9, 155, 154, 213, 1, 139, 237, 194, 206, 10, 114, 218, 209, 130, 122, 23, 9, 218, 48, 88, 15, 5, 68 },
        .transactions_root = .{ 86, 232, 31, 23, 27, 204, 85, 166, 255, 131, 69, 230, 146, 192, 248, 110, 91, 72, 224, 27, 153, 108, 173, 192, 1, 98, 47, 181, 227, 99, 180, 33 },
        .receipts_root = .{ 86, 232, 31, 23, 27, 204, 85, 166, 255, 131, 69, 230, 146, 192, 248, 110, 91, 72, 224, 27, 153, 108, 173, 192, 1, 98, 47, 181, 227, 99, 180, 33 },
        .logs_bloom = .{0} ** 256,
        .difficulty = 17179869184,
        .number = 0,
        .gas_limit = 5000,
        .gas_used = 0,
        .timestamp = 0,
        .extra_data = .{ .buf = .{ 17, 187, 232, 219, 78, 52, 123, 78, 140, 147, 124, 28, 131, 112, 228, 181, 237, 51, 173, 179, 219, 105, 203, 219, 122, 56, 225, 229, 11, 27, 130, 250 }, .len = 32 },
        .mix_hash = .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
        .nonce = .{ 0, 0, 0, 0, 0, 0, 0, 0x42 },
        .base_fee_per_gas = null,
        .withdrawals_root = null,
        .blob_gas_used = null,
        .excess_blob_gas = null,
        .parent_beacon_block_root = null,
        .requests_hash = null,
        .block_access_list_hash = null,
        .slot_number = null,
    },
    .fork_schedule = forks.mainnet_schedule,
};

test "mainnet genesis hash" {
    const expected: [32]u8 = .{ 0xd4, 0xe5, 0x67, 0x40, 0xf8, 0x76, 0xae, 0xf8, 0xc0, 0x10, 0xb8, 0x6a, 0x40, 0xd5, 0xf5, 0x67, 0x45, 0xa1, 0x18, 0xd0, 0x90, 0x6a, 0x34, 0xe6, 0x9a, 0xec, 0x8c, 0x0d, 0xb1, 0xcb, 0x8f, 0xa3 };
    try std.testing.expectEqual(expected, mainnet_config.genesis_header.hash());
}
