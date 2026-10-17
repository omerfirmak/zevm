// Copyright (c) 2025-2026 zevm authors
// SPDX-License-Identifier: MIT OR Apache-2.0

const std = @import("std");
const rlp = @import("rlp");
const keccak256 = @import("../evm/crypto/hash.zig").keccak256;

pub const empty_root_hash: [32]u8 = .{
    0x56, 0xe8, 0x1f, 0x17, 0x1b, 0xcc, 0x55, 0xa6,
    0xff, 0x83, 0x45, 0xe6, 0x92, 0xc0, 0xf8, 0x6e,
    0x5b, 0x48, 0xe0, 0x1b, 0x99, 0x6c, 0xad, 0xc0,
    0x01, 0x62, 0x2f, 0xb5, 0xe3, 0x63, 0xb4, 0x21,
}; // 0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421

pub const Node = union(enum) {
    // Nodes decoded from proofs aren't allocated in key order, so hashing them never frees memory.
    pub const no_frame = std.math.maxInt(u32);

    pub const Branch = struct {
        children: [16]?*Node = @splat(null),
        hash: ?*[32]u8 = null,
        frame: u32 = no_frame,

        pub fn init() Node {
            return Node{ .branch = .{} };
        }
    };
    pub const Extension = struct {
        key: [65]u8,
        key_len: u8,
        child: *Node,
        hash: ?*[32]u8 = null,
        frame: u32 = no_frame,

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
    pub const Leaf = struct {
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
    pub const Hashed = struct {
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

    // Revisit if Node grows or stack tries take values larger than state values.
    pub const stack_size = 512 << 10;

    root: *Node,

    allocator: std.mem.Allocator,
    resolver: ?NodeResolver = null,
    stack: ?std.heap.FixedBufferAllocator = null,

    skip: enum { none, deletions, writes } = .none,
    skipped_deletions: bool = false,

    pub const NodeResolver = struct {
        ptr: *anyopaque,
        resolveFn: *const fn (ptr: *anyopaque, allocator: std.mem.Allocator, path: []const u8, node_hash: [32]u8) anyerror!?[]const u8,
    };

    pub fn init(allocator: std.mem.Allocator) !Self {
        const root = try allocator.create(Node);
        root.* = .empty;
        return Self{
            .root = root,
            .allocator = allocator,
        };
    }

    pub fn initWithStack(allocator: std.mem.Allocator, buffer: *[stack_size]u8) !Self {
        var stack: std.heap.FixedBufferAllocator = .init(buffer);
        const root = try stack.allocator().create(Node);
        root.* = .empty;
        return .{
            .root = root,
            .allocator = allocator,
            .stack = stack,
        };
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
        std.debug.assert(self.stack == null); // stack tries only take updateNoDeletions

        self.skipped_deletions = false;
        defer self.skip = .none;
        self.skip = .deletions;
        try self.updatePass(keys, values);
        if (!self.skipped_deletions) return;
        self.skip = .writes;
        try self.updatePass(keys, values);
    }

    pub fn updateNoDeletions(self: *Self, keys: []const [32]u8, values: [][]const u8) !void {
        std.debug.assert(keys.len != 0);
        std.debug.assert(keys.len == values.len);
        return self.updatePass(keys, values);
    }

    fn updatePass(self: *Self, keys: []const [32]u8, values: [][]const u8) !void {
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
        if ((self.skip == .deletions and value.len == 0) or (self.skip == .writes and value.len != 0)) {
            self.skipped_deletions = true;
            if (keys.*.len > 0) _ = writeHexKey(&keys.*[0], key_buf);
            return self.tailInsert(node, key, path, value, key_buf, keys, values);
        }
        switch (node.*) {
            .empty => {
                if (value.len != 0) node.* = Node.Leaf.init(key, try self.dupeValue(value));
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
                        try self.collapseBranch(node, branch, path);
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
                        // Break before the last byte: wrap in intermediate extension. It is
                        // hashed before being allocated, so its child's frame is freed first.
                        var remainder = Node.Extension.init(ext.key[diff_idx + 1 .. ext.key_len], ext.child);
                        remainder.ext.frame = ext.frame;
                        if (orig_idx < new_idx) try self.hash(&remainder, path.appendSlice(ext.key[0 .. diff_idx + 1]));
                        n = try self.createNode();
                        n.* = remainder;
                    } else {
                        // Break at the last byte: reuse child directly.
                        n = ext.child;
                        if (orig_idx < new_idx) try self.hash(n, path.appendSlice(ext.key[0..ext.key_len]));
                    }

                    // Create the branch that represents the divergence point.
                    var p: *Node.Branch = undefined;
                    if (diff_idx == 0) {
                        // Convert this node to a branch.
                        const ext_frame = ext.frame;
                        node.* = Node.Branch.init();
                        node.branch.frame = ext_frame;
                        p = &node.branch;
                    } else {
                        // Keep as ext with truncated key; insert branch child.
                        ext.child = try self.createNode();
                        ext.child.* = Node.Branch.init();
                        ext.child.branch.frame = self.currentFrame();
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
                        node.branch.frame = self.currentFrame();
                        p = &node.branch;
                    } else {
                        // Convert this leaf into an ext + branch.
                        const ext_frame = self.currentFrame();
                        const child = try self.createNode();
                        child.* = Node.Branch.init();
                        child.branch.frame = self.currentFrame();
                        node.* = Node.Extension.init(leaf.key[0..diff_idx], child);
                        node.ext.frame = ext_frame;
                        p = &child.branch;
                    }

                    const orig_idx = leaf.key[diff_idx];
                    const new_idx = key[diff_idx];
                    // the value is already owned by the trie, no need to copy it again
                    p.children[orig_idx] = try self.createNode();
                    p.children[orig_idx].?.* = Node.Leaf.init(leaf.key[diff_idx + 1 .. leaf.key_len], leaf.val);
                    if (orig_idx < new_idx) try self.hash(p.children[orig_idx].?, path.appendSlice(leaf.key[0 .. diff_idx + 1]));

                    // Insert the new value.
                    p.children[new_idx] = try self.createLeaf(key[diff_idx + 1 ..], value);
                }
                if (keys.*.len > 0) _ = writeHexKey(&keys.*[0], key_buf);
            },
            .hashed => {
                try self.resolveHashed(node, path);
                return self.insert(node, key, path, value, key_buf, keys, values);
            },
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
        const n = try self.createNode();
        n.* = Node.Leaf.init(key, try self.dupeValue(value));
        return n;
    }

    fn resolveHashed(self: *Self, node: *Node, path: Path) !void {
        const resolver = self.resolver orelse return error.SubTrieNotAvailable;
        if (node.hashed.len != 32) return error.SubTrieNotAvailable;
        const node_hash = node.hashed.data;
        const encoded = try resolver.resolveFn(resolver.ptr, self.allocator, path.slice(), node_hash) orelse
            return error.SubTrieNotAvailable;
        errdefer self.allocator.free(encoded);
        try decodeNode(self, node, encoded, null);
    }

    // Collapse a branch that has dropped to 0 or 1 live children after a deletion.
    fn collapseBranch(self: *Self, node: *Node, branch: *Node.Branch, path: Path) !void {
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
            .branch => {
                const new_key: [1]u8 = .{remaining_nibble};
                node.* = Node.Extension.init(&new_key, remaining_child);
            },
            // A hash alone cannot tell whether a sibling's path
            // must merge with this branch's final nibble. Never guess a root.
            .hashed => {
                try self.resolveHashed(remaining_child, path.append(remaining_nibble));
                return self.collapseBranch(node, branch, path);
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
        if (self.skip == .deletions) return;
        const own_frame = switch (node.*) {
            .branch => |branch| branch.frame,
            .ext => |ext| ext.frame,
            else => Node.no_frame,
        };
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
        if (self.stack) |*stack| if (own_frame != Node.no_frame) {
            stack.end_index = own_frame;
        };
    }

    fn createNode(self: *Self) !*Node {
        if (self.stack) |*stack| return stack.allocator().create(Node);
        return self.allocator.create(Node);
    }

    fn currentFrame(self: *const Self) u32 {
        return if (self.stack) |stack| @intCast(stack.end_index) else 0;
    }

    fn dupeValue(self: *Self, value: []const u8) ![]const u8 {
        if (self.stack) |*stack| return stack.allocator().dupe(u8, value);
        return value;
    }
};

pub fn writeHexKey(key: []const u8, buf: *[64]u8) []u8 {
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

fn stackTrieRoot(buffer: *[Trie.stack_size]u8, keys: []const [32]u8, values: [][]const u8, batch_sizes: []const usize) ![32]u8 {
    var trie = try Trie.initWithStack(std.testing.allocator, buffer);
    var start: usize = 0;
    for (batch_sizes) |size| {
        const end = @min(start + size, keys.len);
        if (end == start) continue;
        try trie.updateNoDeletions(keys[start..end], values[start..end]);
        start = end;
    }
    if (start < keys.len) try trie.updateNoDeletions(keys[start..], values[start..]);
    return trie.rootHash();
}

test "stack trie matches the regular trie and stays bounded" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var prng = std.Random.DefaultPrng.init(0x5eed);
    const random = prng.random();

    for ([_]usize{ 1, 2, 17, 300, 5000, 100_000 }) |count| {
        const keys = try a.alloc([32]u8, count);
        for (keys, 0..) |*key, i| {
            random.bytes(key);
            // shared prefixes produce extensions, and their splits
            if (i % 3 == 0) @memset(key[0..random.uintLessThan(usize, 6)], 0xab);
        }
        std.mem.sortUnstable([32]u8, keys, {}, struct {
            fn lessThan(_: void, l: [32]u8, r: [32]u8) bool {
                return std.mem.order(u8, &l, &r) == .lt;
            }
        }.lessThan);
        var unique: usize = 0;
        for (keys) |key| {
            if (unique > 0 and std.mem.eql(u8, &keys[unique - 1], &key)) continue;
            keys[unique] = key;
            unique += 1;
        }
        const values = try a.alloc([]const u8, unique);
        for (values) |*value| {
            const buf = try a.alloc(u8, 1 + random.uintLessThan(usize, 100));
            random.bytes(buf);
            value.* = buf;
        }

        var regular = try Trie.init(a);
        try regular.updateNoDeletions(keys[0..unique], values);
        const expected = try regular.rootHash();

        const buffer = try std.testing.allocator.create([Trie.stack_size]u8);
        defer std.testing.allocator.destroy(buffer);
        try std.testing.expectEqualSlices(u8, &expected, &try stackTrieRoot(buffer, keys[0..unique], values, &.{unique}));
        try std.testing.expectEqualSlices(u8, &expected, &try stackTrieRoot(buffer, keys[0..unique], values, &.{ 1, 2, 3, 5, 8, 13, 21, 34, 55, 89, 144, 233 }));
    }
}

test "stack trie keeps values across batches" {
    var keys: [4][32]u8 = undefined;
    makeKey("1234da", &keys[0]);
    makeKey("1234ea", &keys[1]);
    makeKey("1234fa", &keys[2]);
    makeKey("2000", &keys[3]);
    var vals = [_][]const u8{ "x___________________________1", "x___________________________2", "x___________________________3", "x___________________________4" };
    var regular = try Trie.init(std.heap.c_allocator);
    try regular.update(&keys, &vals);
    const expected = try regular.rootHash();

    const buffer = try std.testing.allocator.create([Trie.stack_size]u8);
    defer std.testing.allocator.destroy(buffer);
    var trie = try Trie.initWithStack(std.testing.allocator, buffer);
    var buf: [1][]const u8 = undefined;
    var value: [29]u8 = undefined;
    for (keys, vals) |key, val| {
        // the caller reuses its value buffer for every batch
        @memcpy(&value, val);
        buf[0] = &value;
        try trie.updateNoDeletions(&.{key}, &buf);
        @memset(&value, 0);
    }
    try std.testing.expectEqualSlices(u8, &expected, &try trie.rootHash());
}

pub const NodesHashMap = std.HashMapUnmanaged([32]u8, []const u8, struct {
    pub fn eql(_: @This(), a: [32]u8, b: [32]u8) bool {
        return std.mem.eql(u8, &a, &b);
    }
    pub fn hash(_: @This(), key: [32]u8) u64 {
        return std.mem.readInt(u64, key[0..8], .native);
    }
}, 80);

pub fn loadFromNodesMap(
    allocator: std.mem.Allocator,
    root: [32]u8,
    nodes: *const NodesHashMap,
    stack_buffer: ?*[Trie.stack_size]u8,
) !Trie {
    var t = if (stack_buffer) |buffer| try Trie.initWithStack(allocator, buffer) else try Trie.init(allocator);
    if (std.mem.eql(u8, &empty_root_hash, &root)) return t;
    t.root.* = Node.Hashed.init(&root);
    try resolveFromMap(&t, t.root, nodes);
    return t;
}

fn resolveFromMap(self: *Trie, node: *Node, nodes: *const NodesHashMap) anyerror!void {
    switch (node.*) {
        .hashed => |hashed| {
            if (hashed.len != 32) return;
            const entry = nodes.getEntryContext(hashed.data, .{}) orelse return;
            try decodeNode(self, node, entry.value_ptr.*, entry.key_ptr);
            try resolveFromMap(self, node, nodes);
        },
        .branch => |branch| for (branch.children) |child| {
            if (child) |c| try resolveFromMap(self, c, nodes);
        },
        .ext => |ext| try resolveFromMap(self, ext.child, nodes),
        .leaf, .empty => {},
    }
}

fn decodeNode(self: *Trie, node: *Node, encoded: []const u8, node_hash: ?*[32]u8) anyerror!void {
    var items: [][]const u8 = undefined;
    _ = try rlp.deserialize([][]const u8, self.allocator, encoded, &items);
    defer self.allocator.free(items);

    if (items.len == 17) {
        node.* = Node.Branch.init();
        node.branch.hash = node_hash;
        for (items[0..16], 0..) |child_payload, i| {
            if (child_payload.len == 0) continue;
            node.branch.children[i] = try decodeChild(self, child_payload);
        }
    } else if (items.len == 2) {
        const key_payload = items[0];
        const value_payload = items[1];

        var key_buf: [65]u8 = undefined;
        const decoded = compactToHex(key_payload, &key_buf);

        if (decoded.is_leaf) {
            node.* = Node.Leaf.init(decoded.nibbles, value_payload);
            node.leaf.hash = node_hash;
        } else {
            if (value_payload.len == 0) return error.MalformedTrieNode;
            node.* = Node.Extension.init(decoded.nibbles, try decodeChild(self, value_payload));
            node.ext.hash = node_hash;
        }
    } else {
        return error.MalformedTrieNode;
    }
}

fn decodeChild(self: *Trie, payload: []const u8) !*Node {
    const child = try self.createNode();
    if (payload.len == 32) {
        child.* = Node.Hashed.init(payload);
    } else {
        try decodeNode(self, child, (payload.ptr - 1)[0 .. payload.len + 1], null);
    }
    return child;
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

test "deleting a leaf requires its remaining sibling preimage" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var leaf_path: [32]u8 = @splat(0);
    leaf_path[0] = 0x30;
    const value_a: [32]u8 = @splat(0xaa);
    const value_b: [32]u8 = @splat(0xbb);
    var encoded_a = std.array_list.Managed(u8).init(a);
    var encoded_b = std.array_list.Managed(u8).init(a);
    try rlp.serialize([2][]const u8, a, .{ &leaf_path, &value_a }, &encoded_a);
    try rlp.serialize([2][]const u8, a, .{ &leaf_path, &value_b }, &encoded_b);
    const hash_a = keccak256(encoded_a.items);
    const hash_b = keccak256(encoded_b.items);
    var branch: [17][]const u8 = @splat(&.{});
    branch[0] = &hash_a;
    branch[1] = &hash_b;
    var encoded_branch = std.array_list.Managed(u8).init(a);
    try rlp.serialize([17][]const u8, a, branch, &encoded_branch);
    const root = keccak256(encoded_branch.items);
    var nodes: NodesHashMap = .empty;
    try nodes.put(a, root, encoded_branch.items);
    try nodes.put(a, hash_a, encoded_a.items);
    var incomplete = try loadFromNodesMap(a, root, &nodes, null);
    const key_a: [32]u8 = @splat(0);
    var values = [_][]const u8{&.{}};
    try std.testing.expectError(error.SubTrieNotAvailable, incomplete.update(&.{key_a}, &values));

    var store: NodesHashMap = .empty;
    try store.put(a, hash_b, encoded_b.items);
    var resolved = try loadFromNodesMap(a, root, &nodes, null);
    resolved.resolver = .{ .ptr = &store, .resolveFn = struct {
        fn resolve(ptr: *anyopaque, _: std.mem.Allocator, path: []const u8, node_hash: [32]u8) anyerror!?[]const u8 {
            try std.testing.expectEqualSlices(u8, &.{1}, path);
            return @as(*NodesHashMap, @ptrCast(@alignCast(ptr))).get(node_hash);
        }
    }.resolve };
    try resolved.update(&.{key_a}, &values);

    try nodes.put(a, hash_b, encoded_b.items);
    var complete = try loadFromNodesMap(a, root, &nodes, null);
    try complete.update(&.{key_a}, &values);
    var remaining_path: [33]u8 = @splat(0);
    remaining_path[0] = 0x20;
    remaining_path[1] = 0x10;
    var expected = std.array_list.Managed(u8).init(a);
    try rlp.serialize([2][]const u8, a, .{ &remaining_path, &value_b }, &expected);
    try std.testing.expectEqualSlices(u8, &keccak256(expected.items), &try complete.rootHash());
    try std.testing.expectEqualSlices(u8, &keccak256(expected.items), &try resolved.rootHash());
}

test "a write in the same batch keeps the branch from collapsing onto a missing sibling" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var leaf_path: [32]u8 = @splat(0);
    leaf_path[0] = 0x30;
    const value_0: [32]u8 = @splat(0xaa);
    const value_3: [32]u8 = @splat(0xbb);
    const value_7: [32]u8 = @splat(0xcc);
    var encoded_0 = std.array_list.Managed(u8).init(a);
    var encoded_3 = std.array_list.Managed(u8).init(a);
    var encoded_7 = std.array_list.Managed(u8).init(a);
    try rlp.serialize([2][]const u8, a, .{ &leaf_path, &value_0 }, &encoded_0);
    try rlp.serialize([2][]const u8, a, .{ &leaf_path, &value_3 }, &encoded_3);
    try rlp.serialize([2][]const u8, a, .{ &leaf_path, &value_7 }, &encoded_7);
    const hash_0 = keccak256(encoded_0.items);
    const hash_3 = keccak256(encoded_3.items);
    const hash_7 = keccak256(encoded_7.items);

    // Branch with leaves under nibbles 0 and 3, the preimage of the first one is not provided
    var branch: [17][]const u8 = @splat(&.{});
    branch[0] = &hash_0;
    branch[3] = &hash_3;
    var encoded_branch = std.array_list.Managed(u8).init(a);
    try rlp.serialize([17][]const u8, a, branch, &encoded_branch);
    const root = keccak256(encoded_branch.items);
    var nodes: NodesHashMap = .empty;
    try nodes.put(a, root, encoded_branch.items);
    try nodes.put(a, hash_3, encoded_3.items);
    var t = try loadFromNodesMap(a, root, &nodes, null);

    // The deletion under 3 sorts before the write under 7, but must not collapse the branch
    var key_3: [32]u8 = @splat(0);
    key_3[0] = 0x30;
    var key_7: [32]u8 = @splat(0);
    key_7[0] = 0x70;
    var values = [_][]const u8{ &.{}, &value_7 };
    try t.update(&.{ key_3, key_7 }, &values);

    var expected_branch: [17][]const u8 = @splat(&.{});
    expected_branch[0] = &hash_0;
    expected_branch[7] = &hash_7;
    var expected = std.array_list.Managed(u8).init(a);
    try rlp.serialize([17][]const u8, a, expected_branch, &expected);
    try std.testing.expectEqualSlices(u8, &keccak256(expected.items), &try t.rootHash());
}
