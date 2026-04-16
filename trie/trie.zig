const std = @import("std");
const rlp = @import("rlp");
const Keccak256 = std.crypto.hash.sha3.Keccak256;

pub const empty_root_hash: [32]u8 = .{
    0x56, 0xe8, 0x1f, 0x17, 0x1b, 0xcc, 0x55, 0xa6,
    0xff, 0x83, 0x45, 0xe6, 0x92, 0xc0, 0xf8, 0x6e,
    0x5b, 0x48, 0xe0, 0x1b, 0x99, 0x6c, 0xad, 0xc0,
    0x01, 0x62, 0x2f, 0xb5, 0xe3, 0x63, 0xb4, 0x21,
}; // 0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421

const Node = union(enum) {
    const Branch = struct {
        children: [16]?*Node = [_]?*Node{null} ** 16,

        pub fn init() Node {
            return Node{ .branch = .{} };
        }
    };
    const Extension = struct {
        key: [65]u8,
        key_len: u8,
        child: *Node,

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

    fba: *std.heap.FixedBufferAllocator,
    fba_initial_index: usize,
    allocator: std.mem.Allocator,

    pub fn init(fba: *std.heap.FixedBufferAllocator) !Self {
        const root = try fba.allocator().create(Node);
        root.* = .empty;
        return Self{
            .root = root,
            .fba = fba,
            .allocator = fba.allocator(),
            .fba_initial_index = fba.end_index,
        };
    }

    pub fn deinit(self: *Self) void {
        self.fba.end_index = self.fba_initial_index;
    }

    pub fn update(self: *Self, key: []const u8, value: []const u8) !void {
        std.debug.assert(value.len != 0);

        var key_buf: [64]u8 = undefined;
        const key_nibbles = writeHexKey(key, &key_buf);
        var path_buf: [64]u8 = undefined;
        try self.insert(self.root, key_nibbles, value, .{
            .buf = &path_buf,
            .len = 0,
        });
    }

    pub fn rootHash(self: *Self) ![32]u8 {
        var path_buf: [64]u8 = undefined;
        try self.hash(self.root, .{ .buf = &path_buf, .len = 0 });
        return self.root.hashed.data;
    }

    fn insert(self: *Self, node: *Node, key: []const u8, value: []const u8, path: Path) !void {
        switch (node.*) {
            .empty => {
                node.* = Node.Leaf.init(key, value);
            },
            .branch => |*branch| {
                const idx = key[0];

                // Hash the nearest non-hashed elder sibling.
                if (idx > 0) {
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
                    branch.children[idx] = try self.createLeaf(key[1..], value);
                } else {
                    try self.insert(branch.children[idx].?, key[1..], value, path.append(key[0]));
                }
            },
            .ext => |*ext| {
                const diff_idx = getDiffIndex(ext.key[0..ext.key_len], key);
                const orig_idx = ext.key[diff_idx];

                if (diff_idx == ext.key_len) {
                    // Full match — recurse into child.
                    try self.insert(
                        ext.child,
                        key[diff_idx..],
                        value,
                        path.appendSlice(key[0..diff_idx]),
                    );
                    return;
                }

                // Keys diverge at diff_idx. Save the original subtree,
                // hashing it immediately since no more keys will enter it.
                var n: *Node = undefined;
                if (diff_idx < ext.key_len - 1) {
                    // Break before the last byte: wrap in intermediate extension.
                    n = try self.allocator.create(Node);
                    n.* = Node.Extension.init(ext.key[diff_idx + 1 .. ext.key_len], ext.child);
                    try self.hash(n, path.appendSlice(ext.key[0 .. diff_idx + 1]));
                } else {
                    // Break at the last byte: reuse child directly.
                    n = ext.child;
                    try self.hash(n, path.appendSlice(ext.key[0..ext.key_len]));
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
                }

                const o = try self.createLeaf(key[diff_idx + 1 ..], value);
                const new_idx = key[diff_idx];
                p.children[orig_idx] = n;
                p.children[new_idx] = o;
            },
            .leaf => |leaf| {
                const diff_idx = getDiffIndex(leaf.key[0..leaf.key_len], key);
                std.debug.assert(diff_idx < leaf.key_len);

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

                // Move original value into a new child leaf and hash it immediately.
                const orig_idx = leaf.key[diff_idx];
                p.children[orig_idx] = try self.createLeaf(leaf.key[diff_idx + 1 .. leaf.key_len], leaf.val);
                try self.hash(p.children[orig_idx].?, path.appendSlice(leaf.key[0 .. diff_idx + 1]));

                // Insert the new value.
                const new_idx = key[diff_idx];
                p.children[new_idx] = try self.createLeaf(key[diff_idx + 1 ..], value);
            },
            .hashed => unreachable,
        }
    }

    fn createLeaf(self: *Self, key: []const u8, value: []const u8) !*Node {
        const n = try self.allocator.create(Node);
        n.* = Node.Leaf.init(key, value);
        return n;
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
                try self.hash(ext.child, path.appendSlice(ext.key[0..ext.key_len]));

                const child_h = ext.child.hashed;
                const encoder = struct { key: []const u8, value: ChildRef };
                try rlp.serialize(encoder, self.allocator, .{
                    .key = hexToCompact(ext.key[0..ext.key_len]),
                    .value = .{ .data = child_h.data[0..child_h.len], .raw = child_h.len < 32 },
                }, &list);
            },
            .leaf => |*leaf| {
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
            var h: [32]u8 = undefined;
            Keccak256.hash(list.items, &h, .{});
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

test "this-file" {
    std.testing.refAllDeclsRecursive(@This());
}

fn verifyCase(cases: []const struct { k: []const u8, v: []const u8 }, expected_hex: *const [64]u8) !void {
    const buf = try std.testing.allocator.alloc(u8, 1024 * 1024);
    defer std.testing.allocator.free(buf);
    var fba = std.heap.FixedBufferAllocator.init(buf);
    var trie = try Trie.init(&fba);
    defer trie.deinit();

    for (cases) |c| {
        var key_buf: [32]u8 = undefined;
        const key = std.fmt.hexToBytes(&key_buf, c.k) catch unreachable;
        try trie.update(key, c.v);
    }

    var expected: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&expected, expected_hex) catch unreachable;

    const root = try trie.rootHash();
    try std.testing.expectEqualSlices(u8, &expected, &root);
}

test "empty trie" {
    const buf = try std.testing.allocator.alloc(u8, 4096);
    defer std.testing.allocator.free(buf);
    var fba = std.heap.FixedBufferAllocator.init(buf);
    var trie = try Trie.init(&fba);
    defer trie.deinit();

    const root = try trie.rootHash();
    try std.testing.expectEqualSlices(u8, &empty_root_hash, &root);
}

test "three leaves in branch" {
    try verifyCase(&.{
        .{ .k = "00", .v = "v_______________________0___0" },
        .{ .k = "70", .v = "v_______________________0___1" },
        .{ .k = "f0", .v = "v_______________________0___2" },
    }, "9e3a01bd8d43efb8e9d4b5506648150b8e3ed1caea596f84ee28e01a72635470");
}

test "nested extensions and branches" {
    try verifyCase(&.{
        .{ .k = "10cc", .v = "v_______________________1___0" },
        .{ .k = "e1fc", .v = "v_______________________1___1" },
        .{ .k = "eefc", .v = "v_______________________1___2" },
    }, "d789567559fd76fe5b7d9cc42f3750f942502ac1c7f2a466e2f690ec4b6c2a7c");
}

test "shared prefix with branch" {
    try verifyCase(&.{
        .{ .k = "baac", .v = "v_______________________2___0" },
        .{ .k = "bbac", .v = "v_______________________2___1" },
        .{ .k = "dacc", .v = "v_______________________2___2" },
    }, "9bcfc5b220a27328deb9dc6ee2e3d46c9ebc9c69e78acda1fa2c7040602c63ca");
}

test "ext split at different depths" {
    try verifyCase(&.{
        .{ .k = "1456711c", .v = "v_______________________4___0" },
        .{ .k = "1456733c", .v = "v_______________________4___1" },
        .{ .k = "30cccccc", .v = "v_______________________4___2" },
    }, "3780ce111f98d15751dfde1eb21080efc7d3914b429e5c84c64db637c55405b3");
}

test "branch diverge at first nibble" {
    try verifyCase(&.{
        .{ .k = "123d", .v = "x___________________________0" },
        .{ .k = "123e", .v = "x___________________________1" },
        .{ .k = "2aaa", .v = "x___________________________2" },
    }, "f869b40e0c55eace1918332ef91563616fbf0755e2b946119679f7ef8e44b514");
}

test "four keys with shared and divergent prefixes" {
    try verifyCase(&.{
        .{ .k = "000000", .v = "x___________________________0" },
        .{ .k = "1234da", .v = "x___________________________1" },
        .{ .k = "1234ea", .v = "x___________________________2" },
        .{ .k = "1234fa", .v = "x___________________________3" },
    }, "65bb3aafea8121111d693ffe34881c14d27b128fd113fa120961f251fe28428d");
}

test "branch with short values" {
    try verifyCase(&.{
        .{ .k = "01", .v = "a" },
        .{ .k = "80", .v = "b" },
        .{ .k = "ee", .v = "c" },
        .{ .k = "ff", .v = "d" },
    }, "bd5a3584d271d459bd4eb95247b2fc88656b3671b60c1125ffe7bc0b689470d0");
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
    }, "bee629dd27a40772b2e1a67ec6db270d26acdf8d3b674dfae27866ad6ae1f48b");
}

test "branch short then long values" {
    try verifyCase(&.{
        .{ .k = "a001", .v = "v1" },
        .{ .k = "b002", .v = "v2" },
        .{ .k = "c003", .v = "v___________________________3" },
        .{ .k = "d004", .v = "v___________________________4" },
    }, "36e60ecb86b9626165e1c6543c42ecbe4d83bca58e8e1124746961511fce362a");
}

test "ext to branch short then long values" {
    try verifyCase(&.{
        .{ .k = "8002", .v = "v1" },
        .{ .k = "8004", .v = "v2" },
        .{ .k = "8008", .v = "v___________________________3" },
        .{ .k = "800d", .v = "v___________________________4" },
    }, "1cad1fdaab1a6fa95d7b780fd680030e423eb76669971368ba04797a8d9cdfc9");
}

test "31-byte children at embedding threshold" {
    try verifyCase(&.{
        .{ .k = "000001", .v = "ZZZZZZZZZ" },
        .{ .k = "000002", .v = "Y" },
        .{ .k = "000003", .v = "XXXXXXXXXXXXXXXXXXXXXXXXXXXX" },
    }, "962c0fffdeef7612a4f7bff1950d67e3e81c878e48b9ae45b3b374253b050bd8");
}
