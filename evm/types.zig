const std = @import("std");
const rlp = @import("rlp");

// Key type for the global contract state storage
pub const StorageLookup = struct {
    address: u256,
    slot: u256,
};

pub const Account = struct {
    nonce: u256,
    balance: u256,
    storage_hash: [32]u8,
    code_hash: [32]u8,

    pub fn isEmptyAccount(self: *const Account) bool {
        return self.nonce == 0 and self.balance == 0 and std.mem.eql(u8, &self.code_hash, &empty_code_hash);
    }

    /// RLP encoding: [nonce, balance, storage_root, code_hash]
    pub fn encodeToRLP(self: Account, allocator: std.mem.Allocator, list: *std.array_list.Managed(u8)) !void {
        const Enc = struct { nonce: u256, balance: u256, storage_root: [32]u8, code_hash: [32]u8 };
        try rlp.serialize(Enc, allocator, .{
            .nonce = self.nonce,
            .balance = self.balance,
            .storage_root = self.storage_hash,
            .code_hash = self.code_hash,
        }, list);
    }
};

// keccak256("") — used to identify accounts with no deployed code
pub const empty_code_hash: [32]u8 = .{
    0xc5, 0xd2, 0x46, 0x01, 0x86, 0xf7, 0x23, 0x3c,
    0x92, 0x7e, 0x7d, 0xb2, 0xdc, 0xc7, 0x03, 0xc0,
    0xe5, 0x00, 0xb6, 0x53, 0xca, 0x82, 0x27, 0x3b,
    0x7b, 0xfa, 0xd8, 0x04, 0x5d, 0x85, 0xa4, 0x70,
};
// keccak256 of an empty trie — used for accounts with no storage
pub const empty_root_hash: [32]u8 = .{
    0x56, 0xe8, 0x1f, 0x17, 0x1b, 0xcc, 0x55, 0xa6,
    0xff, 0x83, 0x45, 0xe6, 0x92, 0xc0, 0xf8, 0x6e,
    0x5b, 0x48, 0xe0, 0x1b, 0x99, 0x6c, 0xad, 0xc0,
    0x01, 0x62, 0x2f, 0xb5, 0xe3, 0x63, 0xb4, 0x21,
};
