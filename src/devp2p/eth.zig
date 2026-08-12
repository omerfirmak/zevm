const std = @import("std");
const rlp = @import("rlp");
const rlpx = @import("rlpx.zig");
const forks = @import("../forks.zig");
const proto = @import("proto.zig");

pub const MessageId = enum(u8) {
    status = 0x00,
    new_block_hashes = 0x01,
    transactions = 0x02,
    get_block_headers = 0x03,
    block_headers = 0x04,
    get_block_bodies = 0x05,
    block_bodies = 0x06,
    new_block = 0x07,
    new_pooled_transaction_hashes = 0x08,
    get_pooled_transactions = 0x09,
    pooled_transactions = 0x0a,
    get_receipts = 0x0f,
    receipts = 0x10,
    block_range_update = 0x11,
    get_block_access_list = 0x12,
    block_access_list = 0x13,
};

pub const Status = struct {
    protocol_version: u32,
    network_id: u64,
    genesis: [32]u8,
    fork_id: forks.Id,
    earliest_block: u64,
    latest_block: u64,
    latest_block_hash: [32]u8,
};

pub const Transactions = []rlp.RawValue;

pub const BlockRangeUpdate = struct {
    earliest_block: u64,
    latest_block: u64,
    latest_block_hash: [32]u8,
};

pub const Message = union(MessageId) {
    status: Status,
    new_block_hashes: rlp.RawValue,
    transactions: Transactions,
    get_block_headers: rlp.RawValue,
    block_headers: rlp.RawValue,
    get_block_bodies: rlp.RawValue,
    block_bodies: rlp.RawValue,
    new_block: rlp.RawValue,
    new_pooled_transaction_hashes: rlp.RawValue,
    get_pooled_transactions: rlp.RawValue,
    pooled_transactions: rlp.RawValue,
    get_receipts: rlp.RawValue,
    receipts: rlp.RawValue,
    block_range_update: BlockRangeUpdate,
    get_block_access_list: rlp.RawValue,
    block_access_list: rlp.RawValue,
};

pub const Config: proto.Config = .{
    .name = "eth",
    .version = 71,
    .message_count = 0x14,
    .required = false,
    .Message = Message,
};

pub const Provider = proto.Provider(Config);
