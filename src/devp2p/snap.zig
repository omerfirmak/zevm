const std = @import("std");
const rlp = @import("rlp");
const rlpx = @import("rlpx.zig");
const proto = @import("proto.zig");

pub const MessageId = enum(u8) {
    get_account_range = 0,
    account_rage = 1,
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

pub const AccountRange = struct {
    id: u64,
    accounts: []rlp.RawValue,
    proof: [][]u8,
};

pub const Message = union(MessageId) {
    get_account_range: GetAccountRange,
    account_rage: AccountRange,
    get_storage_ranges: rlp.RawValue,
    storage_ranges: rlp.RawValue,
    get_byte_codes: rlp.RawValue,
    byte_codes: rlp.RawValue,
    get_trie_nodes: rlp.RawValue,
    trie_nodes: rlp.RawValue,
    get_access_lists: rlp.RawValue,
    access_lists: rlp.RawValue,
};

pub const Config: proto.Config = .{
    .name = "snap",
    .version = 1,
    .message_count = 10,
    .required = false,
    .Message = Message,
};

pub const Snap = proto.Provider(Config);
