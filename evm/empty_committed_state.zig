const types = @import("types");

// An empty committed state implementation.
// Consumers can swap this file with their own via build.zig to back
// account/storage reads with a real database.
pub const CommittedState = struct {
    pub fn account(_: *const @This(), _: u160) types.Account {
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

    pub fn code(_: *const @This(), _: [32]u8) []const u8 {
        unreachable;
    }
};
