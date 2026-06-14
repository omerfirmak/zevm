pub const evm = @import("evm/evm.zig");
pub const state = @import("evm/state.zig");
pub const spec = @import("evm/spec.zig");
pub const Bytecode = @import("evm/bytecode.zig").Bytecode;

pub const StorageTrie = @import("trie/storage_trie.zig").StorageTrie;
pub const AccountTrie = @import("trie/account_trie.zig").AccountTrie;
pub const trie = @import("trie/trie.zig");
pub const Trie = trie.Trie;

pub const chainspec = @import("processor/chainspec.zig");
pub const processor = @import("processor/processor.zig");

pub const types = @import("types.zig");
pub const Fork = @import("forks.zig").Fork;

pub const blobBaseFee = @import("blob_fee.zig").blobBaseFee;

pub const crypto = struct {
    pub const curve = @import("evm/crypto/curve.zig");
    pub const hash = @import("evm/crypto/hash.zig");
};

pub const CommittedState = @import("evm/committed_state.zig").CommittedState;
