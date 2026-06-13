const std = @import("std");
const rlp = @import("rlp");
const keccak256 = @import("../evm/crypto/hash.zig").keccak256;

pub const empty_root_hash: [32]u8 = .{
    0x56, 0xe8, 0x1f, 0x17, 0x1b, 0xcc, 0x55, 0xa6,
    0xff, 0x83, 0x45, 0xe6, 0x92, 0xc0, 0xf8, 0x6e,
    0x5b, 0x48, 0xe0, 0x1b, 0x99, 0x6c, 0xad, 0xc0,
    0x01, 0x62, 0x2f, 0xb5, 0xe3, 0x63, 0xb4, 0x21,
}; // 0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421

const Node = union(enum) {
    const Branch = struct {
        children: [16]?*Node = [_]?*Node{null} ** 16,
        hash: ?*[32]u8 = null,

        pub fn init() Node {
            return Node{ .branch = .{} };
        }
    };
    const Extension = struct {
        key: [65]u8,
        key_len: u8,
        child: *Node,
        hash: ?*[32]u8 = null,

        pub fn init(key: []const u8, child: *Node) Node {
            var n = Node{ .ext = .{
                .key = undefined,
                .key_len = @intCast(key.len),
                .child = child,
            } };
            @memcpy(n.ext.key[0..key.len], key);
            return n;
        }
    };
    const Leaf = struct {
        key: [65]u8,
        key_len: u8,
        val: []const u8,
        hash: ?*[32]u8 = null,

        pub fn init(key: []const u8, val: []const u8) Node {
            var n = Node{ .leaf = .{
                .key = undefined,
                .key_len = @intCast(key.len),
                .val = val,
            } };
            @memcpy(n.leaf.key[0..key.len], key);
            return n;
        }
    };
    const Hashed = struct {
        data: [32]u8,
        len: u8,

        pub fn init(data: []const u8) Node {
            var n = Node{ .hashed = .{
                .data = undefined,
                .len = @intCast(data.len),
            } };
            @memcpy(n.hashed.data[0..data.len], data);
            return n;
        }
    };

    empty: void,
    branch: Branch,
    ext: Extension,
    leaf: Leaf,
    hashed: Hashed,
};

const Path = struct {
    buf: *[64]u8,
    len: usize,

    fn append(self: Path, b: u8) Path {
        self.buf[self.len] = b;
        return .{ .buf = self.buf, .len = self.len + 1 };
    }

    fn appendSlice(self: Path, bytes: []const u8) Path {
        @memcpy(self.buf[self.len..][0..bytes.len], bytes);
        return .{ .buf = self.buf, .len = self.len + bytes.len };
    }

    fn slice(self: Path) []u8 {
        return self.buf[0..self.len];
    }
};

pub const Trie = struct {
    const Self = @This();

    root: *Node,

    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) !Self {
        const root = try allocator.create(Node);
        root.* = .empty;
        return Self{
            .root = root,
            .allocator = allocator,
        };
    }

    pub fn initFromWitness(
        allocator: std.mem.Allocator,
        root: [32]u8,
        nodes: *const std.AutoArrayHashMapUnmanaged([32]u8, []const u8),
    ) !Self {
        if (std.mem.eql(u8, &empty_root_hash, &root)) return Self.init(allocator);
        var t = Self{
            .root = undefined,
            .allocator = allocator,
        };
        t.root = try t.resolveSubTrie(&root, nodes);
        return t;
    }

    fn resolveSubTrie(
        self: *Self,
        payload: []const u8,
        nodes: *const std.AutoArrayHashMapUnmanaged([32]u8, []const u8),
    ) anyerror!*Node {
        const child = try self.allocator.create(Node);
        if (payload.len == 32) {
            if (nodes.getEntry(payload[0..32].*)) |entry| {
                try self.recursiveResolve(child, entry.value_ptr.*, entry.key_ptr, nodes);
            } else {
                child.* = Node.Hashed.init(payload);
            }
        } else {
            try self.recursiveResolve(child, (payload.ptr - 1)[0 .. payload.len + 1], null, nodes);
        }
        return child;
    }

    fn recursiveResolve(
        self: *Self,
        root: *Node,
        root_rlp: []const u8,
        root_hash: ?*[32]u8,
        nodes: *const std.AutoArrayHashMapUnmanaged([32]u8, []const u8),
    ) anyerror!void {
        var items: [][]const u8 = undefined;
        _ = try rlp.deserialize([][]const u8, self.allocator, root_rlp, &items);
        defer self.allocator.free(items);

        if (items.len == 17) {
            root.* = Node.Branch.init();
            root.branch.hash = root_hash;
            for (items[0..16], 0..) |child_payload, i| {
                if (child_payload.len == 0) continue;
                root.branch.children[i] = try self.resolveSubTrie(child_payload, nodes);
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
                root.* = Node.Extension.init(decoded.nibbles, try self.resolveSubTrie(value_payload, nodes));
                root.ext.hash = root_hash;
            }
        } else {
            return error.MalformedTrieNode;
        }
    }

    pub fn get(self: *const Self, key: [32]u8) !?[]const u8 {
        var key_buf: [64]u8 = undefined;

        var key_nibbles = writeHexKey(&key, &key_buf);
        var cur_node = self.root;
        while (true) {
            switch (cur_node.*) {
                .empty => return null,
                .branch => |*b| {
                    cur_node = b.children[key_nibbles[0]] orelse return null;
                    key_nibbles = key_nibbles[1..];
                },
                .ext => |*e| {
                    const ek = e.key[0..e.key_len];
                    if (!std.mem.startsWith(u8, key_nibbles, ek)) return null;

                    cur_node = e.child;
                    key_nibbles = key_nibbles[e.key_len..];
                },
                .leaf => |*l| {
                    if (!std.mem.eql(u8, l.key[0..l.key_len], key_nibbles)) return null;
                    return l.val;
                },
                .hashed => return error.SubTrieNotAvailable,
            }
        }
    }

    pub fn update(self: *Self, keys: []const [32]u8, values: [][]const u8) !void {
        std.debug.assert(keys.len != 0);
        std.debug.assert(keys.len == values.len);

        var key_buf: [64]u8 = undefined;
        const key_nibbles = writeHexKey(&keys[0], &key_buf);
        var path_buf: [64]u8 = undefined;
        var remaining_keys: []const [32]u8 = keys[1..];
        var remaining_values = values[1..];
        try self.insert(self.root, key_nibbles, .{
            .buf = &path_buf,
            .len = 0,
        }, values[0], &key_buf, &remaining_keys, &remaining_values);
    }

    pub fn put(self: *Self, key_bytes: []const u8, value: []const u8) !void {
        var key_buf: [64]u8 = undefined;
        const nibbles = writeHexKey(key_bytes, &key_buf);
        var path_buf: [64]u8 = undefined;
        var ks: []const [32]u8 = &.{};
        var vs: [][]const u8 = &.{};
        try self.insert(self.root, nibbles, .{ .buf = &path_buf, .len = 0 }, value, &key_buf, &ks, &vs);
    }

    pub fn rootHash(self: *Self) ![32]u8 {
        var path_buf: [64]u8 = undefined;
        try self.hash(self.root, .{ .buf = &path_buf, .len = 0 });
        return self.root.hashed.data;
    }

    fn insert(
        self: *Self,
        node: *Node,
        key: []const u8,
        path: Path,
        value: []const u8,

        // rest of the updates
        key_buf: *[64]u8,
        keys: *[]const [32]u8,
        values: *[][]const u8,
    ) anyerror!void {
        switch (node.*) {
            .empty => {
                if (value.len != 0) node.* = Node.Leaf.init(key, value);
                if (keys.*.len > 0) _ = writeHexKey(&keys.*[0], key_buf);
            },
            .branch => |*branch| {
                const idx = key[0];

                // Hash the nearest non-hashed elder sibling.
                // Skipped for deletions: the branch may collapse, requiring the
                // sibling's key — which is lost once hashed.
                if (value.len != 0 and idx > 0) {
                    var i: usize = idx - 1;
                    while (true) : (i -= 1) {
                        if (branch.children[i]) |child| {
                            if (child.* != .hashed) {
                                try self.hash(child, path.append(@intCast(i)));
                            }
                            break;
                        }
                        if (i == 0) break;
                    }
                }

                if (branch.children[idx] == null) {
                    if (value.len != 0) branch.children[idx] = try self.createLeaf(key[1..], value);
                    if (keys.*.len > 0) _ = writeHexKey(&keys.*[0], key_buf);
                } else {
                    try self.insert(branch.children[idx].?, key[1..], path.append(key[0]), value, key_buf, keys, values);
                    if (branch.children[idx].?.* == .empty) {
                        branch.children[idx] = null;
                        collapseBranch(node, branch);
                    }
                }
                branch.hash = null;
            },
            .ext => |*ext| {
                const diff_idx = getDiffIndex(ext.key[0..ext.key_len], key);
                const orig_idx = ext.key[diff_idx];

                if (diff_idx == ext.key_len) {
                    // Full match — recurse into child.
                    try self.insert(ext.child, key[diff_idx..], path.appendSlice(key[0..diff_idx]), value, key_buf, keys, values);
                    // If a deletion collapsed our child into a leaf/ext, merge this ext's key
                    // into the child's key — adjacent ext+leaf or ext+ext is not a valid MPT shape.
                    switch (ext.child.*) {
                        .empty => node.* = .empty,
                        .leaf => |child_leaf| {
                            var new_key: [65]u8 = undefined;
                            @memcpy(new_key[0..ext.key_len], ext.key[0..ext.key_len]);
                            @memcpy(new_key[ext.key_len..][0..child_leaf.key_len], child_leaf.key[0..child_leaf.key_len]);
                            node.* = Node.Leaf.init(new_key[0 .. ext.key_len + child_leaf.key_len], child_leaf.val);
                        },
                        .ext => |child_ext| {
                            var new_key: [65]u8 = undefined;
                            @memcpy(new_key[0..ext.key_len], ext.key[0..ext.key_len]);
                            @memcpy(new_key[ext.key_len..][0..child_ext.key_len], child_ext.key[0..child_ext.key_len]);
                            node.* = Node.Extension.init(new_key[0 .. ext.key_len + child_ext.key_len], child_ext.child);
                        },
                        .branch, .hashed => ext.hash = null,
                    }
                } else if (value.len == 0) {
                    // Key not present — deletion is a no-op.
                    if (keys.*.len > 0) _ = writeHexKey(&keys.*[0], key_buf);
                } else {
                    const new_idx = key[diff_idx];
                    var n: *Node = undefined;
                    if (diff_idx < ext.key_len - 1) {
                        // Break before the last byte: wrap in intermediate extension.
                        n = try self.allocator.create(Node);
                        n.* = Node.Extension.init(ext.key[diff_idx + 1 .. ext.key_len], ext.child);
                        if (orig_idx < new_idx) try self.hash(n, path.appendSlice(ext.key[0 .. diff_idx + 1]));
                    } else {
                        // Break at the last byte: reuse child directly.
                        n = ext.child;
                        if (orig_idx < new_idx) try self.hash(n, path.appendSlice(ext.key[0..ext.key_len]));
                    }

                    // Create the branch that represents the divergence point.
                    var p: *Node.Branch = undefined;
                    if (diff_idx == 0) {
                        // Convert this node to a branch.
                        node.* = Node.Branch.init();
                        p = &node.branch;
                    } else {
                        // Keep as ext with truncated key; insert branch child.
                        ext.child = try self.allocator.create(Node);
                        ext.child.* = Node.Branch.init();
                        p = &ext.child.branch;
                        ext.key_len = @intCast(diff_idx);
                        ext.hash = null;
                    }

                    const o = try self.createLeaf(key[diff_idx + 1 ..], value);
                    p.children[orig_idx] = n;
                    p.children[new_idx] = o;
                    if (keys.*.len > 0) _ = writeHexKey(&keys.*[0], key_buf);
                }
            },
            .leaf => |leaf| {
                const diff_idx = getDiffIndex(leaf.key[0..leaf.key_len], key);

                if (diff_idx == leaf.key_len) {
                    if (value.len == 0) {
                        node.* = .empty;
                    } else {
                        node.leaf.val = value;
                        node.leaf.hash = null;
                    }
                } else if (value.len != 0) {
                    var p: *Node.Branch = undefined;
                    if (diff_idx == 0) {
                        // Convert this leaf into a branch.
                        node.* = Node.Branch.init();
                        p = &node.branch;
                    } else {
                        // Convert this leaf into an ext + branch.
                        const child = try self.allocator.create(Node);
                        child.* = Node.Branch.init();
                        node.* = Node.Extension.init(leaf.key[0..diff_idx], child);
                        p = &child.branch;
                    }

                    const orig_idx = leaf.key[diff_idx];
                    const new_idx = key[diff_idx];
                    p.children[orig_idx] = try self.createLeaf(leaf.key[diff_idx + 1 .. leaf.key_len], leaf.val);
                    if (orig_idx < new_idx) try self.hash(p.children[orig_idx].?, path.appendSlice(leaf.key[0 .. diff_idx + 1]));

                    // Insert the new value.
                    p.children[new_idx] = try self.createLeaf(key[diff_idx + 1 ..], value);
                }
                if (keys.*.len > 0) _ = writeHexKey(&keys.*[0], key_buf);
            },
            .hashed => return error.SubTrieNotAvailable,
        }

        return self.tailInsert(node, key, path, value, key_buf, keys, values);
    }

    inline fn tailInsert(
        self: *Self,
        node: *Node,
        _: []const u8,
        path: Path,
        _: []const u8,
        key_buf: *[64]u8,
        keys: *[]const [32]u8,
        values: *[][]const u8,
    ) anyerror!void {
        if (keys.*.len == 0) return;

        const next_key = key_buf[0 .. keys.*[0].len * 2];
        if (!std.mem.startsWith(u8, next_key, path.slice())) return;

        const next_value = values.*[0];
        keys.* = keys.*[1..];
        values.* = values.*[1..];

        return @call(.always_tail, Trie.insert, .{
            self, node, next_key[path.len..], path, next_value, key_buf, keys, values,
        });
    }

    fn createLeaf(self: *Self, key: []const u8, value: []const u8) !*Node {
        const n = try self.allocator.create(Node);
        n.* = Node.Leaf.init(key, value);
        return n;
    }

    // Collapse a branch that has dropped to 0 or 1 live children after a deletion.
    fn collapseBranch(node: *Node, branch: *Node.Branch) void {
        var count: usize = 0;
        var remaining_nibble: u8 = 0;
        var remaining_child: *Node = undefined;
        for (branch.children, 0..) |child_opt, i| {
            if (child_opt) |child| {
                count += 1;
                remaining_nibble = @intCast(i);
                remaining_child = child;
            }
        }

        if (count == 0) {
            node.* = .empty;
            return;
        }

        if (count > 1) return;

        switch (remaining_child.*) {
            .leaf => |leaf| {
                var new_key: [65]u8 = undefined;
                new_key[0] = remaining_nibble;
                @memcpy(new_key[1..][0..leaf.key_len], leaf.key[0..leaf.key_len]);
                node.* = Node.Leaf.init(new_key[0 .. leaf.key_len + 1], leaf.val);
            },
            .ext => |ext| {
                var new_key: [65]u8 = undefined;
                new_key[0] = remaining_nibble;
                @memcpy(new_key[1..][0..ext.key_len], ext.key[0..ext.key_len]);
                node.* = Node.Extension.init(new_key[0 .. ext.key_len + 1], ext.child);
            },
            .branch, .hashed => {
                const new_key: [1]u8 = .{remaining_nibble};
                node.* = Node.Extension.init(&new_key, remaining_child);
            },
            .empty => unreachable,
        }
    }

    // Wrapper for child node values in RLP encoding. Hashed children (32 bytes)
    // are encoded as RLP strings; embedded children (< 32 bytes, already RLP-encoded)
    // are written as raw bytes to avoid double-encoding.
    const ChildRef = struct {
        data: []const u8,
        raw: bool,

        pub fn encodeToRLP(self: ChildRef, allocator: std.mem.Allocator, list: *std.array_list.Managed(u8)) !void {
            if (self.raw) {
                try list.appendSlice(self.data);
            } else {
                try rlp.serialize([]const u8, allocator, self.data, list);
            }
        }
    };

    fn hash(self: *Self, node: *Node, path: Path) !void {
        var list = std.array_list.Managed(u8).init(self.allocator);
        defer list.deinit();

        switch (node.*) {
            .empty => {
                node.* = Node.Hashed.init(&empty_root_hash);
                return;
            },
            .branch => |*branch| {
                if (branch.hash) |cached| {
                    node.* = Node.Hashed.init(cached);
                    return;
                }
                var children: [17]ChildRef = undefined;
                for (branch.children, 0..) |child, i| {
                    if (child) |c| {
                        if (c.* != .hashed) {
                            try self.hash(c, path.append(@intCast(i)));
                        }
                        children[i] = .{ .data = c.hashed.data[0..c.hashed.len], .raw = c.hashed.len < 32 };
                    } else {
                        children[i] = .{ .data = &[_]u8{}, .raw = false };
                    }
                }
                children[16] = .{ .data = &[_]u8{}, .raw = false };
                try rlp.serialize([17]ChildRef, self.allocator, children, &list);
            },
            .ext => |*ext| {
                if (ext.hash) |cached| {
                    node.* = Node.Hashed.init(cached);
                    return;
                }
                try self.hash(ext.child, path.appendSlice(ext.key[0..ext.key_len]));

                const child_h = ext.child.hashed;
                const encoder = struct { key: []const u8, value: ChildRef };
                try rlp.serialize(encoder, self.allocator, .{
                    .key = hexToCompact(ext.key[0..ext.key_len]),
                    .value = .{ .data = child_h.data[0..child_h.len], .raw = child_h.len < 32 },
                }, &list);
            },
            .leaf => |*leaf| {
                if (leaf.hash) |cached| {
                    node.* = Node.Hashed.init(cached);
                    return;
                }
                leaf.key[leaf.key_len] = 16;
                const encoder = struct { key: []const u8, value: []const u8 };
                try rlp.serialize(encoder, self.allocator, .{
                    .key = hexToCompact(leaf.key[0 .. leaf.key_len + 1]),
                    .value = leaf.val,
                }, &list);
            },
            .hashed => return,
        }

        if (list.items.len < 32 and path.len > 0) {
            node.* = Node.Hashed.init(list.items);
        } else {
            const h = keccak256(list.items);
            node.* = Node.Hashed.init(&h);
        }
    }
};

fn writeHexKey(key: []const u8, buf: *[64]u8) []u8 {
    for (key, 0..) |b, i| {
        buf[i * 2] = b / 16;
        buf[i * 2 + 1] = b % 16;
    }
    return buf[0 .. 2 * key.len];
}

fn getDiffIndex(key1: []const u8, key2: []const u8) usize {
    for (key1, 0..) |key1_nibble, idx| {
        if (key1_nibble != key2[idx]) {
            return idx;
        }
    }
    return key1.len;
}

// hexToCompact converts a hex-nibble key to compact (hex-prefix) encoding in place.
// If the key ends with terminator nibble 16, the leaf flag is set.
// Returns a subslice of the input buffer containing the compact-encoded key.
fn hexToCompact(hex: []u8) []u8 {
    var hex_len = hex.len;
    var first_byte: u8 = 0;

    if (hex_len > 0 and hex[hex_len - 1] == 16) {
        first_byte = 0x20;
        hex_len -= 1;
    }

    const bin_len = hex_len / 2 + 1;
    var ni: usize = 0;
    var bi: usize = 1;

    if (hex_len & 1 == 1) {
        first_byte |= 0x10;
        first_byte |= hex[0];
        ni += 1;
    }

    while (ni < hex_len) {
        hex[bi] = hex[ni] << 4 | hex[ni + 1];
        bi += 1;
        ni += 2;
    }

    hex[0] = first_byte;
    return hex[0..bin_len];
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

fn verifyCase(cases: []const struct { k: []const u8, v: []const u8 }, expected_hex: *const [64]u8) !void {
    var keys: [16][32]u8 = std.mem.zeroes([16][32]u8);
    var vals: [16][]const u8 = undefined;
    for (cases, 0..) |c, i| {
        _ = std.fmt.hexToBytes(keys[i][0 .. c.k.len / 2], c.k) catch unreachable;
        vals[i] = c.v;
    }

    var trie = try Trie.init(std.heap.c_allocator);
    try trie.update(keys[0..cases.len], vals[0..cases.len]);
    const root = try trie.rootHash();

    var expected: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&expected, expected_hex) catch unreachable;
    try std.testing.expectEqualSlices(u8, &expected, &root);
}

test "empty trie" {
    var trie = try Trie.init(std.heap.c_allocator);

    const root = try trie.rootHash();
    try std.testing.expectEqualSlices(u8, &empty_root_hash, &root);
}

test "three leaves in branch" {
    try verifyCase(&.{
        .{ .k = "00", .v = "v_______________________0___0" },
        .{ .k = "70", .v = "v_______________________0___1" },
        .{ .k = "f0", .v = "v_______________________0___2" },
    }, "e28f9a2712908cae0bc9d3399ef4244af6ce6fd3ed29ed158412b990aa925082");
}

test "nested extensions and branches" {
    try verifyCase(&.{
        .{ .k = "10cc", .v = "v_______________________1___0" },
        .{ .k = "e1fc", .v = "v_______________________1___1" },
        .{ .k = "eefc", .v = "v_______________________1___2" },
    }, "40d58dabb3a3ec6d9f2f62606990f5563cb38d0c4c20507257d3f6c49367f201");
}

test "shared prefix with branch" {
    try verifyCase(&.{
        .{ .k = "baac", .v = "v_______________________2___0" },
        .{ .k = "bbac", .v = "v_______________________2___1" },
        .{ .k = "dacc", .v = "v_______________________2___2" },
    }, "059e6351589f8306c3e97cd313168cbb867f857236f18e266a5064bc666f7524");
}

test "ext split at different depths" {
    try verifyCase(&.{
        .{ .k = "1456711c", .v = "v_______________________4___0" },
        .{ .k = "1456733c", .v = "v_______________________4___1" },
        .{ .k = "30cccccc", .v = "v_______________________4___2" },
    }, "aa6f90becd41c8edec13e99af14bcdd64cd28da3ac1edb5ad9bcd36e4da1c8e5");
}

test "branch diverge at first nibble" {
    try verifyCase(&.{
        .{ .k = "123d", .v = "x___________________________0" },
        .{ .k = "123e", .v = "x___________________________1" },
        .{ .k = "2aaa", .v = "x___________________________2" },
    }, "1b7001da4abae619fa081532f1f3183b803c29ecc8e7305d735dfa435fffd6e2");
}

test "four keys with shared and divergent prefixes" {
    try verifyCase(&.{
        .{ .k = "000000", .v = "x___________________________0" },
        .{ .k = "1234da", .v = "x___________________________1" },
        .{ .k = "1234ea", .v = "x___________________________2" },
        .{ .k = "1234fa", .v = "x___________________________3" },
    }, "c93963b6dab2d3a5f6052070687df38c2aa08df758c716f4c65e9095a6a475ab");
}

test "branch with short values" {
    try verifyCase(&.{
        .{ .k = "01", .v = "a" },
        .{ .k = "80", .v = "b" },
        .{ .k = "ee", .v = "c" },
        .{ .k = "ff", .v = "d" },
    }, "c2fca715cf800ab60024a4e44a861b9d729868d67501e8a91d6cad5ea9d03751");
}

test "ext to branch with growing values" {
    try verifyCase(&.{
        .{ .k = "a0", .v = "a" },
        .{ .k = "a1", .v = "b" },
        .{ .k = "a2", .v = "c" },
        .{ .k = "a3", .v = "d" },
        .{ .k = "a4", .v = "e" },
        .{ .k = "a5", .v = "f" },
        .{ .k = "a6", .v = "g" },
    }, "ad7e9543077be1e3283020c5c364727c4da3630887ac47fd12ba4a424a4ae5b8");
}

test "branch short then long values" {
    try verifyCase(&.{
        .{ .k = "a001", .v = "v1" },
        .{ .k = "b002", .v = "v2" },
        .{ .k = "c003", .v = "v___________________________3" },
        .{ .k = "d004", .v = "v___________________________4" },
    }, "7d7ebfde2618ce55941dc997373a3b8af10d2bd2a47f06ac4d8aaaaaec7c9bed");
}

test "ext to branch short then long values" {
    try verifyCase(&.{
        .{ .k = "8002", .v = "v1" },
        .{ .k = "8004", .v = "v2" },
        .{ .k = "8008", .v = "v___________________________3" },
        .{ .k = "800d", .v = "v___________________________4" },
    }, "4c1c5549c4f5389e28c6a559adebdab319860964b256eaed37b89619bb703b58");
}

test "in-place leaf update" {
    var keys: [2][32]u8 = std.mem.zeroes([2][32]u8);
    _ = std.fmt.hexToBytes(&keys[0], "a0") catch unreachable;
    _ = std.fmt.hexToBytes(&keys[1], "a0") catch unreachable;

    // Trie built with two updates to the same key — second value wins.
    var vals = [_][]const u8{ "first", "second" };
    var trie = try Trie.init(std.heap.c_allocator);
    try trie.update(&keys, &vals);
    const updated_root = try trie.rootHash();

    // Trie built with only the final value — must produce the same root.
    var vals2 = [_][]const u8{"second"};
    var trie2 = try Trie.init(std.heap.c_allocator);
    try trie2.update(keys[0..1], &vals2);
    const expected_root = try trie2.rootHash();

    try std.testing.expectEqualSlices(u8, &expected_root, &updated_root);
}

test "31-byte children at embedding threshold" {
    try verifyCase(&.{
        .{ .k = "000001", .v = "ZZZZZZZZZ" },
        .{ .k = "000002", .v = "Y" },
        .{ .k = "000003", .v = "XXXXXXXXXXXXXXXXXXXXXXXXXXXX" },
    }, "d7070f9ad912463b433a562a2328694fdd4cb75d4f5ed452fe0d9fc600d38f2a");
}

fn makeKey(hex: []const u8, out: *[32]u8) void {
    out.* = std.mem.zeroes([32]u8);
    _ = std.fmt.hexToBytes(out[0 .. hex.len / 2], hex) catch unreachable;
}

test "delete sole leaf produces empty root" {
    var keys: [2][32]u8 = undefined;
    makeKey("ab", &keys[0]);
    makeKey("ab", &keys[1]); // same key, delete
    var vals = [_][]const u8{ "hello", "" };

    var trie = try Trie.init(std.heap.c_allocator);
    try trie.update(&keys, &vals);
    const root = try trie.rootHash();

    try std.testing.expectEqualSlices(u8, &empty_root_hash, &root);
}

test "delete then insert different key in same batch" {
    var keys3: [3][32]u8 = undefined;
    makeKey("a0", &keys3[0]);
    makeKey("a0", &keys3[1]);
    makeKey("b0", &keys3[2]);
    var vals3 = [_][]const u8{ "value_a", "", "value_b" };

    var trie = try Trie.init(std.heap.c_allocator);
    try trie.update(&keys3, &vals3);
    const got = try trie.rootHash();

    // Expected: fresh trie with only b0.
    var keys1: [1][32]u8 = undefined;
    makeKey("b0", &keys1[0]);
    var vals1 = [_][]const u8{"value_b"};
    var trie2 = try Trie.init(std.heap.c_allocator);
    try trie2.update(&keys1, &vals1);
    const expected = try trie2.rootHash();

    try std.testing.expectEqualSlices(u8, &expected, &got);
}

test "delete non-existent key is no-op" {
    // Build reference trie with one real key.
    var k: [1][32]u8 = undefined;
    makeKey("b0", &k[0]);
    var v = [_][]const u8{"value_b"};
    var ref = try Trie.init(std.heap.c_allocator);
    try ref.update(&k, &v);
    const expected = try ref.rootHash();

    // Batch that also "deletes" a non-existent key a0 (comes before b0 in sort order).
    var keys2: [2][32]u8 = undefined;
    makeKey("a0", &keys2[0]); // delete of non-existent key
    makeKey("b0", &keys2[1]);
    var vals2 = [_][]const u8{ "", "value_b" };
    var trie = try Trie.init(std.heap.c_allocator);
    try trie.update(&keys2, &vals2);
    const got = try trie.rootHash();

    try std.testing.expectEqualSlices(u8, &expected, &got);
}
