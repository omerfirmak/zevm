const std = @import("std");

comptime {
    _ = @import("types.zig");
    _ = @import("forks.zig");
    _ = @import("trie/trie.zig");
    _ = @import("evm/crypto/ripemd160.zig");
    _ = @import("devp2p/allocator.zig");
}
