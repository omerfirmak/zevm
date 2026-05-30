const std = @import("std");
const evm = @import("zevm");

pub const Errors = error{
    NotFound,
};

pub const CommittedState = struct {
    codes: std.AutoHashMapUnmanaged([32]u8, []const u8),
    state_trie: evm.AccountTrie,
    account_tries: std.AutoHashMapUnmanaged(u160, evm.StorageTrie),

    pub fn init(
        allocator: std.mem.Allocator,
        parent_state_root: [32]u8,
        state: [][]const u8,
        bytecodes: [][]const u8,
        bal: *const evm.types.BlockAccessLists,
    ) !CommittedState {
        var codes: std.AutoHashMapUnmanaged([32]u8, []const u8) = .empty;
        try codes.ensureTotalCapacity(allocator, @intCast(bytecodes.len));

        for (bytecodes) |bytecode| {
            var code_hash: [32]u8 = undefined;
            std.crypto.hash.sha2.Sha256.hash(bytecode, &code_hash, .{});
            codes.putAssumeCapacity(code_hash, bytecode);
        }

        var nodes: std.AutoArrayHashMapUnmanaged([32]u8, []const u8) = .empty;
        try nodes.ensureTotalCapacity(allocator, @intCast(state.len));
        defer nodes.deinit(allocator);

        for (state) |node| {
            var node_hash: [32]u8 = undefined;
            std.crypto.hash.sha2.Sha256.hash(node, &node_hash, .{});
            nodes.putAssumeCapacity(node_hash, node);
        }

        const state_trie = evm.AccountTrie.initFromTrie(
            try evm.Trie.initFromWitness(allocator, parent_state_root, &nodes),
        );

        var account_tries: std.AutoHashMapUnmanaged(u160, evm.StorageTrie) = .empty;
        try account_tries.ensureTotalCapacity(allocator, @intCast(bal.len));

        for (bal.*) |entry| {
            const storage_hash = (try state_trie.get(keccakOfU160(entry.addr))).storage_hash;
            account_tries.putAssumeCapacity(entry.addr, evm.StorageTrie.initFromTrie(
                try evm.Trie.initFromWitness(allocator, storage_hash, &nodes),
            ));
        }

        return .{
            .codes = codes,
            .state_trie = state_trie,
            .account_tries = account_tries,
        };
    }

    pub fn account(_: *const @This(), _: u160) !evm.types.Account {
        return .{
            .balance = 0,
            .nonce = 0,
            .code_hash = evm.types.empty_code_hash,
            .storage_hash = evm.types.empty_root_hash,
        };
    }

    pub fn storage(_: *const @This(), _: evm.types.StorageLookup) !u256 {
        return 0;
    }

    pub fn code(_: *const @This(), _: [32]u8) ![]const u8 {
        return Errors.NotFound;
    }
};

pub fn keccakOfU160(v: u160) [32]u8 {
    var buf: [20]u8 = undefined;
    std.mem.writeInt(u160, &buf, v, .big);
    var out: [32]u8 = undefined;
    std.crypto.hash.sha3.Keccak256.hash(&buf, &out, .{});
    return out;
}

pub fn keccakOfU256(v: u256) [32]u8 {
    var buf: [32]u8 = undefined;
    std.mem.writeInt(u256, &buf, v, .big);
    var out: [32]u8 = undefined;
    std.crypto.hash.sha23Keccak256.hash(&buf, &out, .{});
    return out;
}
