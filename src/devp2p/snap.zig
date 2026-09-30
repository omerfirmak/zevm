const std = @import("std");
const rlp = @import("rlp");
const rlpx = @import("rlpx.zig");
const proto = @import("proto.zig");

pub const MessageId = enum(u8) {
    get_account_range = 0,
    account_range = 1,
    get_storage_ranges = 2,
    storage_ranges = 3,
    get_byte_codes = 4,
    byte_codes = 5,
    get_trie_nodes = 6,
    trie_nodes = 7,
    get_access_lists = 8,
    access_lists = 9,
};

pub const GetAccountRange = struct {
    id: u64,
    root: [32]u8,
    origin: [32]u8,
    limit: [32]u8,
    bytes: u64 = 10_000_000,
};

pub const SlimAccount = struct {
    nonce: u64,
    balance: u256,
    root: []const u8,
    code_hash: []const u8,
};

pub const AccountRange = struct {
    id: u64,
    accounts: []struct { hash: [32]u8, account: rlp.RawValue },
    proof: [][]const u8,
};

pub const GetByteCodes = struct {
    id: u64,
    hashes: [][32]u8,
    bytes: u64 = 10_000_000,
};

pub const ByteCodes = struct {
    id: u64,
    bytecodes: [][]const u8,
};

pub const GetStorageRanges = struct {
    id: u64,
    root_hash: [32]u8,
    account_hashes: [][32]u8,
    starting_hash: [32]u8 = @splat(0),
    limit_hash: [32]u8 = @splat(0xff),
    response_bytes: u64 = 10_000_000,
};

pub const StorageRanges = struct {
    id: u64,
    slots: [][]struct { hash: [32]u8, data: []const u8 },
    proof: [][]const u8,
};

pub const Message = union(MessageId) {
    get_account_range: GetAccountRange,
    account_range: AccountRange,
    get_storage_ranges: GetStorageRanges,
    storage_ranges: StorageRanges,
    get_byte_codes: GetByteCodes,
    byte_codes: ByteCodes,
    get_trie_nodes: rlp.RawValue,
    trie_nodes: rlp.RawValue,
    get_access_lists: rlp.RawValue,
    access_lists: rlp.RawValue,
};

pub const Config: proto.Config = .{
    .name = "snap",
    .version = 1,
    .message_count = 8,
    .required = false,
    .Message = Message,
};

pub const Provider = proto.Provider(Config);
