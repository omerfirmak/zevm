// Copyright (c) 2025-2026 zevm authors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Arena-owned, immutable decoded nodes of a secure (32-byte-key) MPT.
//! A batch borrows input bytes until committed. Authentication follows hash
//! references from a caller-supplied root; missing nodes never imply absence.
//! Commit copies new preimages and rebases decoded slices without parsing again.
//! Sealing materializes mutable zevm nodes in a separate caller-owned arena.
const std = @import("std");
const trie_impl = @import("trie.zig");
const keccak256 = @import("../evm/crypto/hash.zig").keccak256;
const A = std.mem.Allocator;
const Hash = [32]u8;
const Node = trie_impl.Node;
const Store = @This();

const Path = struct { nibbles: [64]u8 = undefined, len: u8 };
const Parsed = union(enum) {
    branch: [16][]const u8,
    extension: struct { path: Path, child: []const u8 },
    leaf: struct { path: Path, value: []const u8 },
};
const Entry = struct { hash: Hash, bytes: []const u8, parsed: Parsed };
const Map = std.AutoHashMapUnmanaged(Hash, *const Entry);

/// The caller supplies an arena whose lifetime covers the store and every
/// mutable trie borrowed from it. Entries never move when the index grows.
allocator: A,
entries: Map = .empty,
encoded_bytes: usize = 0,

pub fn init(arena: A) Store {
    return .{ .allocator = arena };
}

pub const Batch = struct {
    store: *const Store,
    entries: Map = .empty,

    pub fn view(self: *const Batch, cached: bool) View {
        return .{ .store = if (cached) self.store else null, .batch = self };
    }
};

/// Hash each supplied preimage once. Previously decoded entries are borrowed;
/// new entries and the batch index use scratch. Rejection retains no new nodes.
pub fn prepare(self: *const Store, scratch: A, preimages: []const []const u8) !Batch {
    var batch: Batch = .{ .store = self };
    for (preimages) |bytes| {
        const hash = keccak256(bytes);
        if (batch.entries.contains(hash)) continue;
        const entry = self.entries.get(hash) orelse blk: {
            const parsed = try parse(bytes);
            const entry = try scratch.create(Entry);
            entry.* = .{ .hash = hash, .bytes = bytes, .parsed = parsed };
            break :blk entry;
        };
        try batch.entries.put(scratch, hash, entry);
    }
    return batch;
}

/// Call only after all batch claims have authenticated. Supplied preimages,
/// including extra deletion siblings, remain content-addressed hints: caching
/// one never authenticates a state value without a path from the chosen root.
/// OOM may retain a subset; it never changes an existing entry or trie.
pub fn commit(self: *Store, batch: *const Batch) !void {
    var it = batch.entries.valueIterator();
    while (it.next()) |value| {
        const source = value.*;
        if (self.entries.contains(source.hash)) continue;
        const entry = try self.allocator.create(Entry);
        const bytes = try self.allocator.dupe(u8, source.bytes);
        entry.* = source.*;
        entry.bytes = bytes;
        switch (entry.parsed) {
            .branch => |*children| for (children) |*child| {
                child.* = rebase(child.*, source.bytes, bytes);
            },
            .extension => |*ext| ext.child = rebase(ext.child, source.bytes, bytes),
            .leaf => |*leaf| leaf.value = rebase(leaf.value, source.bytes, bytes),
        }
        try self.entries.put(self.allocator, entry.hash, entry);
        self.encoded_bytes += bytes.len;
    }
}

fn rebase(slice: []const u8, from: []const u8, to: []const u8) []const u8 {
    if (slice.len == 0) return &.{};
    const offset = @intFromPtr(slice.ptr) - @intFromPtr(from.ptr);
    return to[offset..][0..slice.len];
}

pub const View = struct {
    store: ?*const Store = null,
    batch: ?*const Batch = null,

    fn entry(self: View, hash: Hash) ?*const Entry {
        if (self.batch) |batch| if (batch.entries.get(hash)) |found| return found;
        return if (self.store) |store| store.entries.get(hash) else null;
    }

    /// The returned value borrows the store/batch. A null value is an exclusion
    /// proven by the requested root; an unresolved reference is an error.
    pub fn lookup(self: View, root: Hash, key: Hash) !?[]const u8 {
        if (std.mem.eql(u8, &root, &trie_impl.empty_root_hash)) return null;
        var current = &(self.entry(root) orelse return error.SubTrieNotAvailable).parsed;
        var inline_node: Parsed = undefined;
        var offset: usize = 0;
        for (0..65) |_| {
            const child = switch (current.*) {
                .branch => |children| blk: {
                    if (offset == 64) return error.MalformedTrieNode;
                    const child = children[nibble(key, offset)];
                    offset += 1;
                    if (child.len == 0) return null;
                    break :blk child;
                },
                .leaf => |leaf| {
                    if (offset + leaf.path.len != 64) return error.MalformedTrieNode;
                    return if (matches(leaf.path, key, offset)) leaf.value else null;
                },
                .extension => |ext| blk: {
                    if (offset + ext.path.len > 64) return error.MalformedTrieNode;
                    if (!matches(ext.path, key, offset)) return null;
                    offset += ext.path.len;
                    break :blk ext.child;
                },
            };
            const ref = try item(child);
            if (ref.list) {
                inline_node = try parse(child);
                current = &inline_node;
            } else {
                current = &(self.entry(ref.payload[0..32].*) orelse return error.SubTrieNotAvailable).parsed;
            }
        }
        return error.MalformedTrieNode;
    }
};

pub fn view(self: *const Store) View {
    return .{ .store = self };
}

/// Copies all mutable nodes, borrowing only immutable hashes and leaf bytes.
/// Hash-map growth, later proof imports and other seals cannot mutate this trie.
pub fn trie(self: *const Store, arena: A, root: Hash) !trie_impl.Trie {
    if (std.mem.eql(u8, &root, &trie_impl.empty_root_hash)) return trie_impl.Trie.init(arena);
    return .{ .allocator = arena, .root = try self.materializeHash(arena, root, 0) };
}

fn materializeHash(self: *const Store, arena: A, hash: Hash, depth: usize) anyerror!*Node {
    if (depth > 64) return error.MalformedTrieNode;
    if (self.entries.get(hash)) |entry| return self.materialize(arena, entry.parsed, &entry.hash, depth);
    const result = try arena.create(Node);
    result.* = Node.Hashed.init(&hash);
    return result;
}

fn materializeChild(self: *const Store, arena: A, bytes: []const u8, depth: usize) anyerror!*Node {
    const ref = try item(bytes);
    if (ref.list) return self.materialize(arena, try parse(bytes), null, depth);
    return self.materializeHash(arena, ref.payload[0..32].*, depth);
}

fn materialize(self: *const Store, arena: A, parsed: Parsed, hash: ?*const Hash, depth: usize) anyerror!*Node {
    if (depth > 64) return error.MalformedTrieNode;
    const result = try arena.create(Node);
    switch (parsed) {
        .branch => |children| {
            if (depth == 64) return error.MalformedTrieNode;
            result.* = Node.Branch.init();
            result.branch.hash = hash;
            for (children, 0..) |child, i| {
                if (child.len != 0) result.branch.children[i] = try self.materializeChild(arena, child, depth + 1);
            }
        },
        .extension => |ext| {
            if (depth + ext.path.len > 64) return error.MalformedTrieNode;
            result.* = Node.Extension.init(ext.path.nibbles[0..ext.path.len], try self.materializeChild(arena, ext.child, depth + ext.path.len));
            result.ext.hash = hash;
        },
        .leaf => |leaf| {
            if (depth + leaf.path.len != 64) return error.MalformedTrieNode;
            result.* = Node.Leaf.init(leaf.path.nibbles[0..leaf.path.len], leaf.value);
            result.leaf.hash = hash;
        },
    }
    return result;
}

fn matches(path: Path, key: Hash, offset: usize) bool {
    if (path.len > 64 - offset) return false;
    for (path.nibbles[0..path.len], 0..) |part, i| if (part != nibble(key, offset + i)) return false;
    return true;
}

fn nibble(key: Hash, offset: usize) u4 {
    return @truncate(if (offset % 2 == 0) key[offset / 2] >> 4 else key[offset / 2]);
}

const Item = struct { payload: []const u8, encoded: []const u8, list: bool };

/// Bounded canonical RLP views keep decoded references tied to the original
/// preimage. Nested children are parsed only as trie nodes, never as strings.
fn item(bytes: []const u8) !Item {
    if (bytes.len == 0) return error.MalformedTrieNode;
    const tag = bytes[0];
    if (tag < 0x80) return .{ .payload = bytes[0..1], .encoded = bytes[0..1], .list = false };
    const list = tag >= 0xc0;
    const short: u8 = if (list) 0xc0 else 0x80;
    const long: u8 = if (list) 0xf7 else 0xb7;
    var offset: usize = 1;
    var len: usize = 0;
    if (tag <= long) {
        len = tag - short;
    } else {
        const size: usize = tag - long;
        if (size > @sizeOf(usize) or size >= bytes.len or bytes[1] == 0) return error.MalformedTrieNode;
        for (bytes[1 .. 1 + size]) |byte| len = (len << 8) | byte;
        if (len < 56) return error.MalformedTrieNode;
        offset += size;
    }
    if (len > bytes.len - offset) return error.MalformedTrieNode;
    if (!list and len == 1 and bytes[offset] < 0x80) return error.MalformedTrieNode;
    return .{ .payload = bytes[offset..][0..len], .encoded = bytes[0 .. offset + len], .list = list };
}

fn childReference(child: Item, empty: bool) ![]const u8 {
    if (child.list) {
        if (child.encoded.len >= 32) return error.MalformedTrieNode;
    } else if (child.payload.len != 32) {
        if (empty and child.payload.len == 0) return &.{};
        return error.MalformedTrieNode;
    }
    return child.encoded;
}

fn parse(bytes: []const u8) !Parsed {
    const outer = try item(bytes);
    if (!outer.list or outer.encoded.len != bytes.len) return error.MalformedTrieNode;
    var fields: [17]Item = undefined;
    var count: usize = 0;
    var at: usize = 0;
    while (at < outer.payload.len) {
        if (count == fields.len) return error.MalformedTrieNode;
        fields[count] = try item(outer.payload[at..]);
        at += fields[count].encoded.len;
        count += 1;
    }
    if (count == 17) {
        // Secure keys have one fixed length: no value can terminate at a branch.
        if (fields[16].list or fields[16].payload.len != 0) return error.MalformedTrieNode;
        var children: [16][]const u8 = undefined;
        for (fields[0..16], &children) |field, *child| child.* = try childReference(field, true);
        return .{ .branch = children };
    }
    if (count != 2 or fields[0].list or fields[0].payload.len == 0) return error.MalformedTrieNode;
    const compact = fields[0].payload;
    const flags = compact[0] >> 4;
    if (flags > 3 or (flags & 1 == 0 and compact[0] & 15 != 0)) return error.MalformedTrieNode;
    const skip: usize = if (flags & 1 != 0) 1 else 2;
    if (compact.len > 33 or compact.len * 2 - skip > 64) return error.MalformedTrieNode;
    var path: Path = .{ .len = @intCast(compact.len * 2 - skip) };
    for (path.nibbles[0..path.len], 0..) |*part, i| {
        const pos = skip + i;
        part.* = if (pos % 2 == 0) compact[pos / 2] >> 4 else compact[pos / 2] & 15;
    }
    if (flags & 2 != 0) {
        if (fields[1].list or fields[1].payload.len == 0) return error.MalformedTrieNode;
        return .{ .leaf = .{ .path = path, .value = fields[1].payload } };
    }
    if (path.len == 0) return error.MalformedTrieNode;
    return .{ .extension = .{ .path = path, .child = try childReference(fields[1], false) } };
}

const rlp = @import("rlp");
const a = std.testing.allocator;

fn inlineFixture() [56]u8 {
    // 63 shared zero nibbles, then a branch with two inline terminal leaves.
    var bytes: [56]u8 = @splat(0);
    bytes[0] = 0xf7;
    bytes[1] = 0xa0;
    bytes[2] = 0x10;
    bytes[34] = 0xd5;
    bytes[35..38].* = .{ 0xc2, 0x20, 0x01 };
    bytes[38..41].* = .{ 0xc2, 0x20, 0x02 };
    @memset(bytes[41..], 0x80);
    return bytes;
}

test "decoded trie snapshots own mutations and borrow stable rebased preimages" {
    var retained = std.heap.ArenaAllocator.init(a);
    defer retained.deinit();
    var snapshots = std.heap.ArenaAllocator.init(a);
    defer snapshots.deinit();
    var store = Store.init(retained.allocator());
    var bytes = inlineFixture();
    const root = keccak256(&bytes);
    const key_a: Hash = @splat(0);
    var key_b = key_a;
    key_b[31] = 1;
    {
        var scratch = std.heap.ArenaAllocator.init(a);
        defer scratch.deinit();
        const batch = try store.prepare(scratch.allocator(), &.{&bytes});
        try std.testing.expectEqualSlices(u8, &.{1}, (try batch.view(false).lookup(root, key_a)).?);
        try store.commit(&batch);
    }
    var legacy_nodes: trie_impl.NodesHashMap = .empty;
    try legacy_nodes.put(snapshots.allocator(), root, try snapshots.allocator().dupe(u8, &bytes));
    @memset(&bytes, 0xaa); // no retained slice may borrow the proof command
    try std.testing.expectEqualSlices(u8, &.{2}, (try store.view().lookup(root, key_b)).?);
    var before_growth = try store.trie(snapshots.allocator(), root);
    {
        var scratch = std.heap.ArenaAllocator.init(a);
        defer scratch.deinit();
        var more: [32][56]u8 = undefined;
        var preimages: [32][]const u8 = undefined;
        for (&more, &preimages, 0..) |*node, *preimage, i| {
            node.* = inlineFixture();
            node[37] = @intCast(i + 3);
            preimage.* = node;
        }
        const batch = try store.prepare(scratch.allocator(), &preimages);
        try store.commit(&batch);
    }
    try std.testing.expectEqual(33, store.entries.count());
    try std.testing.expectEqual(root, try before_growth.rootHash());
    var absent = key_a;
    absent[31] = 2;
    try std.testing.expect(try store.view().lookup(root, absent) == null);
    for ([_][]const u8{ &.{3}, &.{} }) |value| {
        var legacy = try trie_impl.loadFromNodesMap(snapshots.allocator(), root, &legacy_nodes);
        var candidate = try store.trie(snapshots.allocator(), root);
        var values = [_][]const u8{value};
        try legacy.update(&.{key_a}, &values);
        try candidate.update(&.{key_a}, &values);
        try std.testing.expectEqual(try legacy.rootHash(), try candidate.rootHash());
        var unchanged = try store.trie(snapshots.allocator(), root);
        try std.testing.expectEqual(root, try unchanged.rootHash());
        try std.testing.expectEqualSlices(u8, &.{1}, (try store.view().lookup(root, key_a)).?);
    }
}

test "staged nodes complete only requested views and cannot mutate old snapshots" {
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const alloc = arena.allocator();
    var path: [32]u8 = @splat(0);
    path[0] = 0x30;
    var leaf_a = std.array_list.Managed(u8).init(alloc);
    var leaf_b = std.array_list.Managed(u8).init(alloc);
    const value_a: Hash = @splat(0xaa);
    const value_b: Hash = @splat(0xbb);
    try rlp.serialize([2][]const u8, alloc, .{ &path, &value_a }, &leaf_a);
    try rlp.serialize([2][]const u8, alloc, .{ &path, &value_b }, &leaf_b);
    const hash_a = keccak256(leaf_a.items);
    const hash_b = keccak256(leaf_b.items);
    var children: [17][]const u8 = @splat(&.{});
    children[0] = &hash_a;
    children[1] = &hash_b;
    var branch = std.array_list.Managed(u8).init(alloc);
    try rlp.serialize([17][]const u8, alloc, children, &branch);
    const root = keccak256(branch.items);
    const key_a: Hash = @splat(0);
    var key_b = key_a;
    key_b[0] = 0x10;
    var store = Store.init(alloc);
    const initial = try store.prepare(alloc, &.{ branch.items, leaf_a.items });
    try store.commit(&initial);
    const before = try store.trie(alloc, root);
    try std.testing.expectError(error.SubTrieNotAvailable, store.view().lookup(root, key_b));
    var incomplete = try store.trie(alloc, root);
    var deletion = [_][]const u8{&.{}};
    try std.testing.expectError(error.SubTrieNotAvailable, incomplete.update(&.{key_a}, &deletion));
    const more = try store.prepare(alloc, &.{leaf_b.items});
    try std.testing.expectError(error.SubTrieNotAvailable, more.view(false).lookup(root, key_b));
    try std.testing.expectEqualSlices(u8, &value_b, (try more.view(true).lookup(root, key_b)).?);
    try std.testing.expectError(error.SubTrieNotAvailable, store.view().lookup(root, key_b));
    try store.commit(&more);
    try std.testing.expectEqualSlices(u8, &value_b, (try store.view().lookup(root, key_b)).?);
    try std.testing.expectError(error.SubTrieNotAvailable, before.get(key_b));
    const after = try store.trie(alloc, root);
    try std.testing.expectEqualSlices(u8, &value_b, (try after.get(key_b)).?);
    var complete = try store.trie(alloc, root);
    try complete.update(&.{key_a}, &deletion);
    var remaining_path: [33]u8 = @splat(0);
    remaining_path[0] = 0x20;
    remaining_path[1] = 0x10;
    var expected = std.array_list.Managed(u8).init(alloc);
    try rlp.serialize([2][]const u8, alloc, .{ &remaining_path, &value_b }, &expected);
    try std.testing.expectEqual(keccak256(expected.items), try complete.rootHash());
    try std.testing.expectError(error.SubTrieNotAvailable, store.view().lookup(@splat(0xcc), key_a));
    try std.testing.expect(try store.view().lookup(trie_impl.empty_root_hash, key_a) == null);
}

test "decoded trie rejects truncated noncanonical and malformed nodes without publishing" {
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const alloc = arena.allocator();
    const store = Store.init(alloc);
    const bytes = inlineFixture();
    for (0..bytes.len) |len| try std.testing.expectError(error.MalformedTrieNode, store.prepare(alloc, &.{bytes[0..len]}));
    for ([_][]const u8{
        &.{0xc0},
        &.{ 0xc2, 0x80, 0x01 }, // empty compact path
        &.{ 0xc2, 0x21, 0x01 }, // nonzero padding in an even path
        &.{ 0xc2, 0x40, 0x01 }, // unknown compact flag
        &.{ 0xc2, 0x00, 0x01 }, // empty extension / non-reference child
        &.{ 0xc2, 0x20, 0xc0 }, // a leaf value must be a string
        &.{ 0xc2, 0x20, 0x80 }, // absent value encoded as a leaf
        &.{ 0xc3, 0x81, 0x20, 0x01 }, // noncanonical string
        &.{ 0xf8, 0x02, 0x20, 0x01 }, // noncanonical list
        &.{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff },
    }) |malformed| try std.testing.expectError(error.MalformedTrieNode, store.prepare(alloc, &.{malformed}));
    try std.testing.expectEqual(0, store.entries.count());
}

fn allocationFailureCase(allocator: std.mem.Allocator) !void {
    var retained = std.heap.ArenaAllocator.init(allocator);
    defer retained.deinit();
    var scratch = std.heap.ArenaAllocator.init(allocator);
    defer scratch.deinit();
    var output = std.heap.ArenaAllocator.init(allocator);
    defer output.deinit();
    var store = Store.init(retained.allocator());
    var bytes = inlineFixture();
    const root = keccak256(&bytes);
    const key: Hash = @splat(0);
    const first = try store.prepare(scratch.allocator(), &.{&bytes});
    try store.commit(&first);
    var before = try store.trie(output.allocator(), root);
    defer {
        // A failed later import/materialization cannot damage retained entries
        // or hashes borrowed by an earlier snapshot.
        const value = store.view().lookup(root, key) catch unreachable;
        std.debug.assert(value.?.len == 1 and value.?[0] == 1);
        std.debug.assert(std.mem.eql(u8, &(before.rootHash() catch unreachable), &root));
    }
    bytes[37] = 3;
    const more = try store.prepare(scratch.allocator(), &.{&bytes});
    try store.commit(&more);
    const after = try store.trie(output.allocator(), root);
    try std.testing.expectEqualSlices(u8, &.{1}, (try after.get(key)).?);
}

test "decoded trie allocation failures preserve existing views and release all arenas" {
    const deterministic: std.mem.Allocator = .{ .ptr = a.ptr, .vtable = &.{
        .alloc = a.vtable.alloc,
        .resize = std.mem.Allocator.noResize,
        .remap = std.mem.Allocator.noRemap,
        .free = a.vtable.free,
    } };
    try std.testing.checkAllAllocationFailures(deterministic, allocationFailureCase, .{});
}
