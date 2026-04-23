const std = @import("std");
const rlp = @import("rlp");

// Key type for the global contract state storage
pub const StorageLookup = struct {
    address: u256,
    slot: u256,
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

pub const BlockHeader = struct {
    parent_hash: [32]u8,
    ommers_hash: [32]u8,
    beneficiary: [20]u8,
    state_root: [32]u8,
    transactions_root: [32]u8,
    receipts_root: [32]u8,
    logs_bloom: [256]u8,
    difficulty: u256,
    number: u64,
    gas_limit: u64,
    gas_used: u64,
    timestamp: u64,
    extra_data: []const u8,
    mix_hash: [32]u8,
    nonce: [8]u8,
    base_fee_per_gas: u64,
    withdrawals_root: [32]u8,
    blob_gas_used: u64,
    excess_blob_gas: u64,
    parent_beacon_block_root: [32]u8,
    requests_hash: [32]u8,
};

test "header decode encode" {
    const allocator = std.testing.allocator;
    const hex = "f90257a00000000000000000000000000000000000000000000000000000000000000000a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347940000000000000000000000000000000000000000a0f62f562b9be5b076ad074beee3d34e25ecda5ad7e0a615067dba4c37174a8afba056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b901000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000080808407270e00808000a0000000000000000000000000000000000000000000000000000000000000000088000000000000000007a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b4218080a00000000000000000000000000000000000000000000000000000000000000000a0e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    const bytes = try allocator.alloc(u8, hex.len / 2);
    defer allocator.free(bytes);
    _ = try std.fmt.hexToBytes(bytes, hex);

    var header: BlockHeader = undefined;
    _ = try rlp.deserialize(BlockHeader, allocator, bytes, &header);

    try std.testing.expectEqualStrings(&std.fmt.bytesToHex(header.parent_hash, .lower), "0000000000000000000000000000000000000000000000000000000000000000");
    try std.testing.expectEqualStrings(&std.fmt.bytesToHex(header.ommers_hash, .lower), "1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347");
    try std.testing.expectEqualStrings(&std.fmt.bytesToHex(header.beneficiary, .lower), "0000000000000000000000000000000000000000");
    try std.testing.expectEqualStrings(&std.fmt.bytesToHex(header.state_root, .lower), "f62f562b9be5b076ad074beee3d34e25ecda5ad7e0a615067dba4c37174a8afb");
    try std.testing.expectEqualStrings(&std.fmt.bytesToHex(header.transactions_root, .lower), "56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421");
    try std.testing.expectEqualStrings(&std.fmt.bytesToHex(header.receipts_root, .lower), "56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421");
    try std.testing.expectEqualStrings(&std.fmt.bytesToHex(header.logs_bloom, .lower), "00" ** 256);
    try std.testing.expectEqual(header.difficulty, 0);
    try std.testing.expectEqual(header.number, 0);
    try std.testing.expectEqual(header.gas_limit, 0x07270e00);
    try std.testing.expectEqual(header.gas_used, 0);
    try std.testing.expectEqual(header.timestamp, 0);
    try std.testing.expectEqualSlices(u8, header.extra_data, &[1]u8{0});
    try std.testing.expectEqualStrings(&std.fmt.bytesToHex(header.mix_hash, .lower), "0000000000000000000000000000000000000000000000000000000000000000");
    try std.testing.expectEqual(std.mem.readInt(u64, &header.nonce, .big), 0);
    try std.testing.expectEqual(header.base_fee_per_gas, 0x7);
    try std.testing.expectEqualStrings(&std.fmt.bytesToHex(header.withdrawals_root, .lower), "56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421");
    try std.testing.expectEqual(header.blob_gas_used, 0);
    try std.testing.expectEqual(header.excess_blob_gas, 0);
    try std.testing.expectEqualStrings(&std.fmt.bytesToHex(header.parent_beacon_block_root, .lower), "0000000000000000000000000000000000000000000000000000000000000000");
    try std.testing.expectEqualStrings(&std.fmt.bytesToHex(header.requests_hash, .lower), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

    var encoded = std.array_list.Managed(u8).init(allocator);
    defer encoded.deinit();
    try rlp.serialize(BlockHeader, allocator, header, &encoded);
    try std.testing.expectEqualSlices(u8, bytes, encoded.items);
}

pub const Withdrawal = struct {
    index: u64,
    validator_index: u64,
    address: [20]u8,
    amount: u64, // gwei
};

pub const Block = struct {
    header: BlockHeader,
    transactions: []Transaction,
    uncles: []BlockHeader,
    withdrawals: []Withdrawal,
};

pub const AccessListEntry = struct {
    address: [20]u8,
    storage_keys: [][32]u8,
};

pub const AuthorizationTuple = struct {
    chain_id: u256,
    address: [20]u8,
    nonce: u64,
    v: u64,
    r: u256,
    s: u256,
};

pub const Transaction = union(enum) {
    pub const LegacyTx = struct {
        nonce: u64,
        gas_price: u256,
        gas_limit: u64,
        to: ?[20]u8,
        value: u256,
        data: []const u8,
        v: u256,
        r: u256,
        s: u256,
    };

    pub const AccessListTx = struct {
        chain_id: u64,
        nonce: u64,
        gas_price: u256,
        gas_limit: u64,
        to: ?[20]u8,
        value: u256,
        data: []const u8,
        access_list: []AccessListEntry,
        v: u256,
        r: u256,
        s: u256,
    };

    pub const DynamicFeeTx = struct {
        chain_id: u64,
        nonce: u64,
        gas_priority_fee: u256,
        gas_price: u256,
        gas_limit: u64,
        to: ?[20]u8,
        value: u256,
        data: []const u8,
        access_list: []AccessListEntry,
        v: u256,
        r: u256,
        s: u256,
    };

    pub const BlobTx = struct {
        chain_id: u64,
        nonce: u64,
        gas_priority_fee: u256,
        gas_price: u256,
        gas_limit: u64,
        to: [20]u8,
        value: u256,
        data: []const u8,
        access_list: []AccessListEntry,
        max_fee_per_blob_gas: u256,
        blob_hashes: [][32]u8,
        v: u256,
        r: u256,
        s: u256,
    };

    pub const SetCodeTx = struct {
        chain_id: u64,
        nonce: u64,
        gas_priority_fee: u256,
        gas_price: u256,
        gas_limit: u64,
        to: [20]u8,
        value: u256,
        data: []const u8,
        access_list: []AccessListEntry,
        auth_list: []AuthorizationTuple,
        v: u256,
        r: u256,
        s: u256,
    };

    legacy: LegacyTx,
    access_list: AccessListTx,
    dynamic: DynamicFeeTx,
    blob: BlobTx,
    set_code: SetCodeTx,

    pub fn decodeFromRLP(self: *@This(), allocator: std.mem.Allocator, serialized: []const u8) !usize {
        if (serialized[0] >= 0xc0)
            return self.decodeTyped(LegacyTx, "legacy", allocator, serialized);
        if (serialized[0] < 0x80) {
            const payload = serialized[1..];
            return switch (serialized[0]) {
                1 => self.decodeTyped(AccessListTx, "access_list", allocator, payload),
                2 => self.decodeTyped(DynamicFeeTx, "dynamic", allocator, payload),
                3 => self.decodeTyped(BlobTx, "blob", allocator, payload),
                4 => self.decodeTyped(SetCodeTx, "set_code", allocator, payload),
                else => error.InvalidTransaction,
            };
        }
        // 0x80..0xbf: byte-string wrapper used for typed txs inside a block body.
        var inner: []const u8 = undefined;
        const consumed = try rlp.deserialize([]const u8, allocator, serialized, &inner);
        if (inner.len == 0 or inner[0] == 0 or inner[0] >= 0x80) return error.InvalidTransaction;
        _ = try self.decodeFromRLP(allocator, inner);
        return consumed;
    }

    fn decodeTyped(self: *Transaction, comptime T: type, comptime tag: []const u8, allocator: std.mem.Allocator, bytes: []const u8) !usize {
        var inner: T = undefined;
        const size = try rlp.deserialize(T, allocator, bytes, &inner);
        self.* = @unionInit(Transaction, tag, inner);
        return size;
    }
};

test "legacy tx decode" {
    const allocator = std.testing.allocator;
    const hex = "f860800a830186a0941257767465d91292f29c15df1e25e063daed8b59808026a0a7eaaef383a6b7fc7192d2adbdaf0331b4d82f352f89956ce8be97e9fe5d0590a01a5ae493968f37d3462cdca0d30f0e3bb4799025e48682bcb1eefe152c847d52";

    const bytes = try allocator.alloc(u8, hex.len / 2);
    defer allocator.free(bytes);
    _ = try std.fmt.hexToBytes(bytes, hex);

    var tx: Transaction = undefined;
    _ = try rlp.deserialize(Transaction, allocator, bytes, &tx);

    const legacy = tx.legacy;
    try std.testing.expectEqual(0, legacy.nonce);
    try std.testing.expectEqual(10, legacy.gas_price);
    try std.testing.expectEqual(0x186a0, legacy.gas_limit);
    try std.testing.expectEqualSlices(u8, &legacy.to.?, &[20]u8{ 0x12, 0x57, 0x76, 0x74, 0x65, 0xd9, 0x12, 0x92, 0xf2, 0x9c, 0x15, 0xdf, 0x1e, 0x25, 0xe0, 0x63, 0xda, 0xed, 0x8b, 0x59 });
    try std.testing.expectEqual(0, legacy.value);
    try std.testing.expectEqualSlices(u8, &.{}, legacy.data);
    try std.testing.expectEqual(0x26, legacy.v);
    try std.testing.expectEqual(0xa7eaaef383a6b7fc7192d2adbdaf0331b4d82f352f89956ce8be97e9fe5d0590, legacy.r);
    try std.testing.expectEqual(0x1a5ae493968f37d3462cdca0d30f0e3bb4799025e48682bcb1eefe152c847d52, legacy.s);
}

test "access list tx decode" {
    const allocator = std.testing.allocator;
    const hex = "01f89b01800a8301e974943985d8b9eda311b84b1e2fbf91f04e7a6454c0638080f838f7943985d8b9eda311b84b1e2fbf91f04e7a6454bf63e1a0000000000000000000000000000000000000000000000000000000000000000001a005ee32c650fc04868b37df068031089e862bc0544bbbce0f54d5320b764453e8a021700a8028a27f20f344c19cbca030b47c66c011707c889b5808997002202155";

    const bytes = try allocator.alloc(u8, hex.len / 2);
    defer allocator.free(bytes);
    _ = try std.fmt.hexToBytes(bytes, hex);

    var tx: Transaction = undefined;
    _ = try tx.decodeFromRLP(allocator, bytes);
    defer allocator.free(tx.access_list.access_list);
    defer allocator.free(tx.access_list.access_list[0].storage_keys);

    const al = tx.access_list;
    try std.testing.expectEqual(1, al.chain_id);
    try std.testing.expectEqual(0, al.nonce);
    try std.testing.expectEqual(10, al.gas_price);
    try std.testing.expectEqual(0x01e974, al.gas_limit);
    try std.testing.expectEqualSlices(u8, &al.to.?, &[20]u8{ 0x39, 0x85, 0xd8, 0xb9, 0xed, 0xa3, 0x11, 0xb8, 0x4b, 0x1e, 0x2f, 0xbf, 0x91, 0xf0, 0x4e, 0x7a, 0x64, 0x54, 0xc0, 0x63 });
    try std.testing.expectEqual(0, al.value);
    try std.testing.expectEqualSlices(u8, &.{}, al.data);
    try std.testing.expectEqual(1, al.access_list.len);
    try std.testing.expectEqualSlices(u8, &al.access_list[0].address, &[20]u8{ 0x39, 0x85, 0xd8, 0xb9, 0xed, 0xa3, 0x11, 0xb8, 0x4b, 0x1e, 0x2f, 0xbf, 0x91, 0xf0, 0x4e, 0x7a, 0x64, 0x54, 0xbf, 0x63 });
    try std.testing.expectEqual(1, al.access_list[0].storage_keys.len);
    try std.testing.expectEqual([_]u8{0} ** 32, al.access_list[0].storage_keys[0]);
    try std.testing.expectEqual(0x01, al.v);
    try std.testing.expectEqual(0x05ee32c650fc04868b37df068031089e862bc0544bbbce0f54d5320b764453e8, al.r);
    try std.testing.expectEqual(0x21700a8028a27f20f344c19cbca030b47c66c011707c889b5808997002202155, al.s);
}

test "dynamic fee tx decode" {
    const allocator = std.testing.allocator;
    const hex = "02f90118018080078277df94dafca687af63469aaa606dfa0c924c26fd7a02a680b8443078303130323033303430353036303730383039313031313132313331343135313631373138313932303231323232333234323532363237323832393330333133323333f870f7940000000000000000000000000000000000000001e1a000000000000000000000000000000000000000000000000000000000000060a7f7940000000000000000000000000000000000000002e1a000000000000000000000000000000000000000000000000000000000000060a801a0806dd23d4716eed215313dab8cb5c7b14771e948b178f4f34f0b4747d305e27fa041551a1bcebec5057950e14ed0b5eebff9b28566456594b3c6df2df01807ea3b";

    const bytes = try allocator.alloc(u8, hex.len / 2);
    defer allocator.free(bytes);
    _ = try std.fmt.hexToBytes(bytes, hex);

    var tx: Transaction = undefined;
    _ = try tx.decodeFromRLP(allocator, bytes);
    defer allocator.free(tx.dynamic.access_list);
    defer allocator.free(tx.dynamic.access_list[1].storage_keys);
    defer allocator.free(tx.dynamic.access_list[0].storage_keys);

    const dyn = tx.dynamic;
    try std.testing.expectEqual(1, dyn.chain_id);
    try std.testing.expectEqual(0, dyn.nonce);
    try std.testing.expectEqual(0, dyn.gas_priority_fee);
    try std.testing.expectEqual(7, dyn.gas_price);
    try std.testing.expectEqual(0x77df, dyn.gas_limit);
    try std.testing.expectEqualSlices(u8, &dyn.to.?, &[20]u8{ 0xda, 0xfc, 0xa6, 0x87, 0xaf, 0x63, 0x46, 0x9a, 0xaa, 0x60, 0x6d, 0xfa, 0x0c, 0x92, 0x4c, 0x26, 0xfd, 0x7a, 0x02, 0xa6 });
    try std.testing.expectEqual(0, dyn.value);
    try std.testing.expectEqual(68, dyn.data.len);
    try std.testing.expectEqual(2, dyn.access_list.len);
    try std.testing.expectEqualSlices(u8, &dyn.access_list[0].address, &[20]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 });
    try std.testing.expectEqual(1, dyn.access_list[0].storage_keys.len);
    try std.testing.expectEqual([32]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x60, 0xa7 }, dyn.access_list[0].storage_keys[0]);
    try std.testing.expectEqualSlices(u8, &dyn.access_list[1].address, &[20]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2 });
    try std.testing.expectEqual(1, dyn.access_list[1].storage_keys.len);
    try std.testing.expectEqual([32]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x60, 0xa8 }, dyn.access_list[1].storage_keys[0]);
    try std.testing.expectEqual(1, dyn.v);
    try std.testing.expectEqual(0x806dd23d4716eed215313dab8cb5c7b14771e948b178f4f34f0b4747d305e27f, dyn.r);
    try std.testing.expectEqual(0x41551a1bcebec5057950e14ed0b5eebff9b28566456594b3c6df2df01807ea3b, dyn.s);
}

test "blob tx decode" {
    const allocator = std.testing.allocator;
    const hex = "03f9012c0180070e8307a120947087da8cced1db00179a9bf66638281b3f30b93f8080c064f8c6a00100000000000000000000000000000000000000000000000000000000000000a00100000000000000000000000000000000000000000000000000000000000001a00100000000000000000000000000000000000000000000000000000000000002a00100000000000000000000000000000000000000000000000000000000000003a00100000000000000000000000000000000000000000000000000000000000004a0010000000000000000000000000000000000000000000000000000000000000580a0c8894bfb86a345dc7be3ee07535ec394526b36343db66d1ba98d7f3cd9674269a06d8a5169c9668d664b9d578814062d5c4dcb9a81f9eb7e2a43a07ea5aec9a7fa";

    const bytes = try allocator.alloc(u8, hex.len / 2);
    defer allocator.free(bytes);
    _ = try std.fmt.hexToBytes(bytes, hex);

    var tx: Transaction = undefined;
    _ = try tx.decodeFromRLP(allocator, bytes);
    defer allocator.free(tx.blob.blob_hashes);
    defer allocator.free(tx.blob.access_list);

    const b = tx.blob;
    try std.testing.expectEqual(1, b.chain_id);
    try std.testing.expectEqual(0, b.nonce);
    try std.testing.expectEqual(7, b.gas_priority_fee);
    try std.testing.expectEqual(0x0e, b.gas_price);
    try std.testing.expectEqual(0x07a120, b.gas_limit);
    try std.testing.expectEqualSlices(u8, &b.to, &[20]u8{ 0x70, 0x87, 0xda, 0x8c, 0xce, 0xd1, 0xdb, 0x00, 0x17, 0x9a, 0x9b, 0xf6, 0x66, 0x38, 0x28, 0x1b, 0x3f, 0x30, 0xb9, 0x3f });
    try std.testing.expectEqual(0, b.value);
    try std.testing.expectEqualSlices(u8, &.{}, b.data);
    try std.testing.expectEqual(0, b.access_list.len);
    try std.testing.expectEqual(0x64, b.max_fee_per_blob_gas);
    try std.testing.expectEqual(6, b.blob_hashes.len);
    try std.testing.expectEqual([32]u8{ 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, b.blob_hashes[0]);
    try std.testing.expectEqual([32]u8{ 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5 }, b.blob_hashes[5]);
    try std.testing.expectEqual(0, b.v);
    try std.testing.expectEqual(0xc8894bfb86a345dc7be3ee07535ec394526b36343db66d1ba98d7f3cd9674269, b.r);
    try std.testing.expectEqual(0x6d8a5169c9668d664b9d578814062d5c4dcb9a81f9eb7e2a43a07ea5aec9a7fa, b.s);
}

test "set code tx decode" {
    const allocator = std.testing.allocator;
    const hex = "04f9013d01808007830f424094000f3df6d732807ef1319fb7b8bb8522d0beac0280a0000000000000000000000000000000000000000000000000000000000000000cf85bf85994000f3df6d732807ef1319fb7b8bb8522d0beac02f842a0000000000000000000000000000000000000000000000000000000000000000ca0000000000000000000000000000000000000000000000000000000000000200bf85cf85a809400000000000000000000000000000000000000008080a08af6634a4c93d4597b27318d46501d4ff47915770c20ba0901de5b261418e195a043e1bf4d229c22a15d4490c055195bc1061d918ca5ac0d3dc77e480da2bb79b480a0359d2cf1f05e133c1e37f16bc00a4870968019f8b1dac1487770bc0226e15c9da050ad44a1dffc82b89f84a333737a263f24854eba6e37f0fb8396f891d521d09a";

    const bytes = try allocator.alloc(u8, hex.len / 2);
    defer allocator.free(bytes);
    _ = try std.fmt.hexToBytes(bytes, hex);

    var tx: Transaction = undefined;
    _ = try tx.decodeFromRLP(allocator, bytes);
    defer allocator.free(tx.set_code.auth_list);
    defer allocator.free(tx.set_code.access_list);
    defer allocator.free(tx.set_code.access_list[0].storage_keys);

    const sc = tx.set_code;
    try std.testing.expectEqual(1, sc.chain_id);
    try std.testing.expectEqual(0, sc.nonce);
    try std.testing.expectEqual(0, sc.gas_priority_fee);
    try std.testing.expectEqual(7, sc.gas_price);
    try std.testing.expectEqual(0x0f4240, sc.gas_limit);
    try std.testing.expectEqualSlices(u8, &sc.to, &[20]u8{ 0x00, 0x0f, 0x3d, 0xf6, 0xd7, 0x32, 0x80, 0x7e, 0xf1, 0x31, 0x9f, 0xb7, 0xb8, 0xbb, 0x85, 0x22, 0xd0, 0xbe, 0xac, 0x02 });
    try std.testing.expectEqual(0, sc.value);
    try std.testing.expectEqual(32, sc.data.len);
    try std.testing.expectEqual(1, sc.access_list.len);
    try std.testing.expectEqualSlices(u8, &sc.access_list[0].address, &[20]u8{ 0x00, 0x0f, 0x3d, 0xf6, 0xd7, 0x32, 0x80, 0x7e, 0xf1, 0x31, 0x9f, 0xb7, 0xb8, 0xbb, 0x85, 0x22, 0xd0, 0xbe, 0xac, 0x02 });
    try std.testing.expectEqual(2, sc.access_list[0].storage_keys.len);
    try std.testing.expectEqual([32]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0c }, sc.access_list[0].storage_keys[0]);
    try std.testing.expectEqual([32]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x20, 0x0b }, sc.access_list[0].storage_keys[1]);
    try std.testing.expectEqual(1, sc.auth_list.len);
    try std.testing.expectEqual(0, sc.auth_list[0].chain_id);
    try std.testing.expectEqualSlices(u8, &sc.auth_list[0].address, &[_]u8{0} ** 20);
    try std.testing.expectEqual(0, sc.auth_list[0].nonce);
    try std.testing.expectEqual(0, sc.auth_list[0].v);
    try std.testing.expectEqual(0x8af6634a4c93d4597b27318d46501d4ff47915770c20ba0901de5b261418e195, sc.auth_list[0].r);
    try std.testing.expectEqual(0x43e1bf4d229c22a15d4490c055195bc1061d918ca5ac0d3dc77e480da2bb79b4, sc.auth_list[0].s);
    try std.testing.expectEqual(0, sc.v);
    try std.testing.expectEqual(0x359d2cf1f05e133c1e37f16bc00a4870968019f8b1dac1487770bc0226e15c9d, sc.r);
    try std.testing.expectEqual(0x50ad44a1dffc82b89f84a333737a263f24854eba6e37f0fb8396f891d521d09a, sc.s);
}

test "block decode" {
    const allocator = std.testing.allocator;
    const hex = "f902ccf90259a05f31dccb126a9b9250c19e20a937e0676aee59aa6a9bd7c573871bd820ab0bf5a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347942adc25665018aa1fe0e6bc666dac8fc2697ff9baa08b4283adbb2dc2fd4551a3010aabfd83256bd701810433820fbbc3426356439ea0cd00fdff88a9c84bf2761409e7544eba8b7fc13baf4118fe84b48f68313a8116a06363485005a5cae5b903c3085b077d8b668552fb8aa354458f3966fe5aaf87dab901000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000080018407270e0082d01f0c80a0000000000000000000000000000000000000000000000000000000000000000088000000000000000007a021e0dfc23997c7eca5831dbc08b50422d07c64b5e5e2bc3036bfe4cfb9354b028080a00000000000000000000000000000000000000000000000000000000000000000a0e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855f853f851800a830f424080808560016000f325a0d9cb76289e52c083d6ece97e9239171c88041cb11b3157e53dbb0b844493d855a02c3e5f2047750246a95fc62594d55b220ccfd2f493e7d6a849e96c39562d7a95c0d9d880809467154c748835ff0aede33129d700a9ee8ff03fb001";

    const bytes = try allocator.alloc(u8, hex.len / 2);
    defer allocator.free(bytes);
    _ = try std.fmt.hexToBytes(bytes, hex);

    var block: Block = undefined;
    _ = try rlp.deserialize(Block, allocator, bytes, &block);
    defer allocator.free(block.withdrawals);
    defer allocator.free(block.uncles);
    defer allocator.free(block.transactions);

    try std.testing.expectEqualStrings(&std.fmt.bytesToHex(block.header.parent_hash, .lower), "5f31dccb126a9b9250c19e20a937e0676aee59aa6a9bd7c573871bd820ab0bf5");
    try std.testing.expectEqual(1, block.header.number);
    try std.testing.expectEqual(0x07270e00, block.header.gas_limit);
    try std.testing.expectEqual(0xd01f, block.header.gas_used);
    try std.testing.expectEqual(0x0c, block.header.timestamp);

    try std.testing.expectEqual(1, block.transactions.len);
    const legacy = block.transactions[0].legacy;
    try std.testing.expectEqual(0, legacy.nonce);
    try std.testing.expectEqual(10, legacy.gas_price);
    try std.testing.expectEqual(0x0f4240, legacy.gas_limit);
    try std.testing.expect(legacy.to == null);
    try std.testing.expectEqual(0, legacy.value);
    try std.testing.expectEqualSlices(u8, &.{ 0x60, 0x01, 0x60, 0x00, 0xf3 }, legacy.data);
    try std.testing.expectEqual(0x25, legacy.v);
    try std.testing.expectEqual(0xd9cb76289e52c083d6ece97e9239171c88041cb11b3157e53dbb0b844493d855, legacy.r);
    try std.testing.expectEqual(0x2c3e5f2047750246a95fc62594d55b220ccfd2f493e7d6a849e96c39562d7a95, legacy.s);

    try std.testing.expectEqual(0, block.uncles.len);

    try std.testing.expectEqual(1, block.withdrawals.len);
    try std.testing.expectEqual(0, block.withdrawals[0].index);
    try std.testing.expectEqual(0, block.withdrawals[0].validator_index);
    try std.testing.expectEqualSlices(u8, &block.withdrawals[0].address, &[20]u8{ 0x67, 0x15, 0x4c, 0x74, 0x88, 0x35, 0xff, 0x0a, 0xed, 0xe3, 0x31, 0x29, 0xd7, 0x00, 0xa9, 0xee, 0x8f, 0xf0, 0x3f, 0xb0 });
    try std.testing.expectEqual(1, block.withdrawals[0].amount);
}

test "block with blob tx decode" {
    const allocator = std.testing.allocator;
    const hex = "f902f3f90261a037e5f7fb1ee096e498bf72bc1b7dfafce1551cc998e09aa466d376947e213481a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347942adc25665018aa1fe0e6bc666dac8fc2697ff9baa0de4fad7dbed6dca9754c682a08305a433767b46a72e5ac028b3a5c78fd827024a002fbf1f1e81b18a2d5c3f98a2d514988293b2fb498f9a98b17f6ab3d8eb0d1e0a0c117ad0158b04d4277c8a0d1b440360bf3f011ad7caccf8740df472c96e8f5ccb901000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000080018407270e0082a8618203e800a0000000000000000000000000000000000000000000000000000000000000000088000000000000000007a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b4218302000083080000a00000000000000000000000000000000000000000000000000000000000000000a0e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855f88bb88903f886018080648307a120947de408e42300f874f525796be23efaad2bf5e7900180c001e1a0010000000000000000000000000000000000000000000000000000000000000001a0f88308d7d02722f540eb6fb7580ba51c1629c6d6640d05427d7b6deefa58b098a066c6a312283650c41e0f7ab3f66df39c36a331e9113ba33a837522040db2e3ebc0c0";

    const bytes = try allocator.alloc(u8, hex.len / 2);
    defer allocator.free(bytes);
    _ = try std.fmt.hexToBytes(bytes, hex);

    var block: Block = undefined;
    _ = try rlp.deserialize(Block, allocator, bytes, &block);
    defer allocator.free(block.withdrawals);
    defer allocator.free(block.uncles);
    defer {
        allocator.free(block.transactions[0].blob.access_list);
        allocator.free(block.transactions[0].blob.blob_hashes);
        allocator.free(block.transactions);
    }

    try std.testing.expectEqualStrings(&std.fmt.bytesToHex(block.header.parent_hash, .lower), "37e5f7fb1ee096e498bf72bc1b7dfafce1551cc998e09aa466d376947e213481");
    try std.testing.expectEqual(1, block.header.number);
    try std.testing.expectEqual(0x07270e00, block.header.gas_limit);
    try std.testing.expectEqual(0xa861, block.header.gas_used);
    try std.testing.expectEqual(0x03e8, block.header.timestamp);
    try std.testing.expectEqual(0x020000, block.header.blob_gas_used);
    try std.testing.expectEqual(0x080000, block.header.excess_blob_gas);
    try std.testing.expectEqual(0x07, block.header.base_fee_per_gas);
    try std.testing.expectEqualStrings(&std.fmt.bytesToHex(block.header.requests_hash, .lower), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

    try std.testing.expectEqual(1, block.transactions.len);
    const b = block.transactions[0].blob;
    try std.testing.expectEqual(1, b.chain_id);
    try std.testing.expectEqual(0, b.nonce);
    try std.testing.expectEqual(0, b.gas_priority_fee);
    try std.testing.expectEqual(0x64, b.gas_price);
    try std.testing.expectEqual(0x07a120, b.gas_limit);
    try std.testing.expectEqualSlices(u8, &b.to, &[20]u8{ 0x7d, 0xe4, 0x08, 0xe4, 0x23, 0x00, 0xf8, 0x74, 0xf5, 0x25, 0x79, 0x6b, 0xe2, 0x3e, 0xfa, 0xad, 0x2b, 0xf5, 0xe7, 0x90 });
    try std.testing.expectEqual(1, b.value);
    try std.testing.expectEqualSlices(u8, &.{}, b.data);
    try std.testing.expectEqual(0, b.access_list.len);
    try std.testing.expectEqual(1, b.max_fee_per_blob_gas);
    try std.testing.expectEqual(1, b.blob_hashes.len);
    try std.testing.expectEqual([32]u8{ 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, b.blob_hashes[0]);
    try std.testing.expectEqual(1, b.v);
    try std.testing.expectEqual(0xf88308d7d02722f540eb6fb7580ba51c1629c6d6640d05427d7b6deefa58b098, b.r);
    try std.testing.expectEqual(0x66c6a312283650c41e0f7ab3f66df39c36a331e9113ba33a837522040db2e3eb, b.s);

    try std.testing.expectEqual(0, block.uncles.len);
    try std.testing.expectEqual(0, block.withdrawals.len);
}
