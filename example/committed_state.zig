const std = @import("std");
const types = @import("types");

// Example committed state that pre-funds a sender and deploys a contract.
pub const CommittedState = struct {
    const sender: u160 = 0xdeadbeef;
    const contract: u160 = 0xcafe;

    const bytecode = [_]u8{
        0x60, 0x2a, 0x60, 0x00, 0x52, // PUSH1 42, PUSH1 0, MSTORE
        0x63, 0xde, 0xad, 0xbe, 0xef, // PUSH4 0xdeadbeef  (topic)
        0x60, 0x20, 0x60, 0x00, 0xa1, // PUSH1 32, PUSH1 0, LOG1
        0x60, 0x20, 0x60, 0x00, 0xf3, // PUSH1 32, PUSH1 0, RETURN
    };
    const code_hash: [32]u8 = [_]u8{ 0x13, 0x37 } ++ [_]u8{0x00} ** 30;

    pub fn account(_: *const @This(), addr: u160) types.Account {
        if (addr == sender) {
            return .{
                .nonce = 0,
                .balance = 1_000_000_000_000_000_000, // 1 ETH
                .code_hash = types.empty_code_hash,
                .storage_hash = types.empty_root_hash,
            };
        }
        if (addr == contract) {
            return .{
                .nonce = 1,
                .balance = 0,
                .code_hash = code_hash,
                .storage_hash = types.empty_root_hash,
            };
        }
        return .{
            .balance = 0,
            .nonce = 0,
            .code_hash = types.empty_code_hash,
            .storage_hash = types.empty_root_hash,
        };
    }

    pub fn storage(_: *const @This(), _: types.StorageLookup) u256 {
        return 0;
    }

    pub fn code(_: *const @This(), hash: [32]u8) []const u8 {
        if (std.mem.eql(u8, &hash, &code_hash)) return &bytecode;
        unreachable;
    }
};
