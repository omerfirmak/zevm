const std = @import("std");
const rlp = @import("rlp");
const trie = @import("zevm").trie;
const Trie = trie.Trie;
const Node = trie.Node;

pub const HashMap = std.HashMapUnmanaged([32]u8, []const u8, struct {
    pub fn eql(_: @This(), a: [32]u8, b: [32]u8) bool {
        return std.mem.eql(u8, &a, &b);
    }
    pub fn hash(_: @This(), key: [32]u8) u64 {
        return std.mem.readInt(u64, key[0..8], .native);
    }
}, 80);

pub fn initFromWitness(
    allocator: std.mem.Allocator,
    root: [32]u8,
    nodes: *const HashMap,
) !Trie {
    if (std.mem.eql(u8, &trie.empty_root_hash, &root)) return Trie.init(allocator);
    var t = Trie{
        .root = undefined,
        .allocator = allocator,
    };
    t.root = try resolveSubTrie(&t, &root, nodes);
    return t;
}

fn resolveSubTrie(
    self: *Trie,
    payload: []const u8,
    nodes: *const HashMap,
) anyerror!*Node {
    const child = try self.allocator.create(Node);
    if (payload.len == 32) {
        if (nodes.getEntryContext(payload[0..32].*, .{})) |entry| {
            try recursiveResolve(self, child, entry.value_ptr.*, entry.key_ptr, nodes);
        } else {
            child.* = Node.Hashed.init(payload);
        }
    } else {
        try recursiveResolve(self, child, (payload.ptr - 1)[0 .. payload.len + 1], null, nodes);
    }
    return child;
}

fn recursiveResolve(
    self: *Trie,
    root: *Node,
    root_rlp: []const u8,
    root_hash: ?*[32]u8,
    nodes: *const HashMap,
) anyerror!void {
    var items: [][]const u8 = undefined;
    _ = try rlp.deserialize([][]const u8, self.allocator, root_rlp, &items);
    defer self.allocator.free(items);

    if (items.len == 17) {
        root.* = Node.Branch.init();
        root.branch.hash = root_hash;
        for (items[0..16], 0..) |child_payload, i| {
            if (child_payload.len == 0) continue;
            root.branch.children[i] = try resolveSubTrie(self, child_payload, nodes);
        }
    } else if (items.len == 2) {
        const key_payload = items[0];
        const value_payload = items[1];

        var key_buf: [65]u8 = undefined;
        const decoded = compactToHex(key_payload, &key_buf);

        if (decoded.is_leaf) {
            root.* = Node.Leaf.init(decoded.nibbles, value_payload);
            root.leaf.hash = root_hash;
        } else {
            if (value_payload.len == 0) return error.MalformedTrieNode;
            root.* = Node.Extension.init(decoded.nibbles, try resolveSubTrie(self, value_payload, nodes));
            root.ext.hash = root_hash;
        }
    } else {
        return error.MalformedTrieNode;
    }
}

fn compactToHex(compact: []const u8, out_buf: *[65]u8) struct { is_leaf: bool, nibbles: []u8 } {
    const flags = compact[0] >> 4;
    const is_leaf = (flags & 0x2) != 0;
    const odd = (flags & 0x1) != 0;

    var i: usize = 0;
    if (odd) {
        out_buf[i] = compact[0] & 0x0F;
        i += 1;
    }
    var j: usize = 1;
    while (j < compact.len) : (j += 1) {
        out_buf[i] = compact[j] >> 4;
        out_buf[i + 1] = compact[j] & 0x0F;
        i += 2;
    }
    return .{ .is_leaf = is_leaf, .nibbles = out_buf[0..i] };
}
