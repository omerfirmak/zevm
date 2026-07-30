const std = @import("std");

const NUM_BUCKET = 25;

fn Slab(comptime Size: usize) type {
    return extern union {
        buf: [Size]u8,
        next: ?*Slab(Size),
    };
}

pub const SlabAllocator = struct {
    const Self = @This();

    parent: std.mem.Allocator,
    frees: [NUM_BUCKET]std.atomic.Value(Head),

    // Free-list head
    const Head = packed struct(u128) {
        ptr: usize = 0,
        tag: u64 = 0,
    };

    pub fn init(parent: std.mem.Allocator) Self {
        return .{
            .parent = parent,
            .frees = [_]std.atomic.Value(Head){std.atomic.Value(Head).init(.{})} ** NUM_BUCKET,
        };
    }

    pub fn alloc(self: *Self, size: u32) ![]u8 {
        if (size == 0) return &.{};
        if (size > 1 << (NUM_BUCKET - 1)) return error.RequestedSizeTooBig;
        return switch (bucketIndex(size)) {
            inline 0...NUM_BUCKET - 1 => |i| self.allocSlab(i),
            else => unreachable,
        };
    }

    fn allocSlab(self: *Self, comptime index: u8) ![]u8 {
        const SlabType = Slab(1 << index);
        while (true) {
            const old = self.frees[index].load(.acquire);
            if (old.ptr == 0) {
                const slab = try self.parent.create(SlabType);
                return &slab.buf;
            }
            const node: *SlabType = @ptrFromInt(old.ptr);
            const new: Head = .{ .ptr = @intFromPtr(node.next), .tag = old.tag +% 1 };
            if (self.frees[index].cmpxchgWeak(old, new, .acq_rel, .acquire) == null)
                return &node.buf;
        }
    }

    pub fn free(self: *Self, buf: []u8) void {
        if (buf.len == 0) return;
        std.debug.assert(buf.len <= 1 << (NUM_BUCKET - 1));
        return switch (bucketIndex(buf.len)) {
            inline 0...NUM_BUCKET - 1 => |i| self.freeSlab(i, buf.ptr),
            else => unreachable,
        };
    }

    fn freeSlab(self: *Self, comptime index: u8, buf: [*]u8) void {
        const size = 1 << index;
        const SlabType = Slab(size);
        const slab: *SlabType = @alignCast(@fieldParentPtr("buf", @as(*[size]u8, @ptrCast(buf))));
        while (true) {
            const old = self.frees[index].load(.acquire);
            slab.next = @ptrFromInt(old.ptr);
            const new: Head = .{ .ptr = @intFromPtr(slab), .tag = old.tag +% 1 };
            if (self.frees[index].cmpxchgWeak(old, new, .acq_rel, .acquire) == null)
                return;
        }
    }

    pub fn allocator(self: *Self) std.mem.Allocator {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable: std.mem.Allocator.VTable = .{
        .alloc = vtableAlloc,
        .resize = vtableResize,
        .remap = vtableRemap,
        .free = vtableFree,
    };

    fn vtableAlloc(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, _: usize) ?[*]u8 {
        const max_alignment = std.mem.Alignment.fromByteUnits(@alignOf(Slab(256)));
        const self: *Self = @ptrCast(@alignCast(ctx));
        if (@intFromEnum(alignment) > @intFromEnum(max_alignment)) return null;
        if (len > 1 << (NUM_BUCKET - 1)) return null;
        const buf = self.alloc(@intCast(len)) catch return null;
        return buf.ptr;
    }

    fn vtableResize(_: *anyopaque, memory: []u8, _: std.mem.Alignment, new_len: usize, _: usize) bool {
        return sameBucket(memory.len, new_len);
    }

    fn vtableRemap(_: *anyopaque, memory: []u8, _: std.mem.Alignment, new_len: usize, _: usize) ?[*]u8 {
        return if (sameBucket(memory.len, new_len)) memory.ptr else null;
    }

    fn vtableFree(ctx: *anyopaque, memory: []u8, _: std.mem.Alignment, _: usize) void {
        const self: *Self = @ptrCast(@alignCast(ctx));
        self.free(memory);
    }

    fn bucketIndex(size: usize) u32 {
        const effective: u32 = @max(255, @as(u32, @intCast(size)) - 1);
        return 32 - @clz(effective);
    }

    fn sameBucket(old_len: usize, new_len: usize) bool {
        if (new_len == 0 or new_len > 1 << (NUM_BUCKET - 1)) return false;
        return bucketIndex(old_len) == bucketIndex(new_len);
    }
};

const test_parent = std.heap.page_allocator;

test "allocSlab rounds size up to a power-of-two slab, minimum 256" {
    var slabs = SlabAllocator.init(test_parent);
    try std.testing.expectEqual(@as(usize, 256), (try slabs.alloc(1)).len);
    try std.testing.expectEqual(@as(usize, 256), (try slabs.alloc(123)).len);
    try std.testing.expectEqual(@as(usize, 256), (try slabs.alloc(256)).len);
    try std.testing.expectEqual(@as(usize, 512), (try slabs.alloc(257)).len);
    try std.testing.expectEqual(@as(usize, 1024), (try slabs.alloc(1000)).len);
}

test "free returns the slab to its bucket for reuse" {
    var slabs = SlabAllocator.init(test_parent);
    const allocator = slabs.allocator();
    const a = try allocator.alloc(u8, 123);
    allocator.free(a);
    const b = try allocator.alloc(u8, 123); // same bucket -> should reuse a's slab
    try std.testing.expectEqual(a.ptr, b.ptr);
}

test "each alloc from an empty bucket mints a distinct slab" {
    var slabs = SlabAllocator.init(test_parent);
    const allocator = slabs.allocator();
    var bufs: [10][]u8 = undefined;
    for (&bufs) |*b| b.* = try allocator.alloc(u8, 100); // same bucket, none freed yet
    // every live allocation is distinct
    for (0..bufs.len) |i| {
        for (i + 1..bufs.len) |j| {
            try std.testing.expect(bufs[i].ptr != bufs[j].ptr);
        }
    }
    for (bufs) |b| allocator.free(b);
}

test "zero-size alloc and free are no-ops" {
    var slabs = SlabAllocator.init(test_parent);
    const allocator = slabs.allocator();
    const z = try allocator.alloc(u8, 0);
    try std.testing.expectEqual(@as(usize, 0), z.len);
    allocator.free(z); // must not crash or corrupt a bucket
}

test "oversized request is rejected" {
    var slabs = SlabAllocator.init(test_parent);
    const allocator = slabs.allocator();
    try std.testing.expectError(error.OutOfMemory, allocator.alloc(u8, (1 << (NUM_BUCKET - 1)) + 1));
}

test "alloc/free round-trips by requested length" {
    var slabs = SlabAllocator.init(test_parent);
    const allocator = slabs.allocator();
    const p = try allocator.alloc(u8, 1234);
    allocator.free(p);
    const q = try allocator.alloc(u8, 1234);
    try std.testing.expectEqual(p.ptr, q.ptr);
    allocator.free(q);
}

test "over-alignment is rejected" {
    var slabs = SlabAllocator.init(test_parent);
    const a = slabs.allocator();
    const ok = try a.alignedAlloc(u8, .@"8", 64);
    a.free(ok);
    try std.testing.expectError(error.OutOfMemory, a.alignedAlloc(u8, .@"16", 64));
}

test "resize stays in place only within the same bucket" {
    var slabs = SlabAllocator.init(test_parent);
    const a = slabs.allocator();
    const p = try a.alloc(u8, 100); // bucket 8 (256-byte slab)
    defer a.free(p);
    try std.testing.expect(a.resize(p, 250)); // still bucket 8 -> in place
    try std.testing.expect(!a.resize(p, 300)); // bucket 9 -> refused
}

test "remap is in place within a bucket, null across buckets" {
    var slabs = SlabAllocator.init(test_parent);
    const a = slabs.allocator();
    const p = try a.alloc(u8, 100);
    defer a.free(p);
    // Same bucket: genuine in-place remap, same pointer.
    const same = a.remap(p, 200) orelse return error.RemapFailed;
    try std.testing.expectEqual(p.ptr, same.ptr);
    // Crosses buckets: null, signalling the caller to alloc + copy + free.
    try std.testing.expect(a.remap(p, 5000) == null);
}

test "realloc across buckets preserves contents" {
    var slabs = SlabAllocator.init(test_parent);
    const a = slabs.allocator();
    var p = try a.alloc(u8, 100);
    for (p, 0..) |*b, i| b.* = @truncate(i);
    // remap returns null here, so realloc falls back to alloc + copy + free.
    p = try a.realloc(p, 5000);
    try std.testing.expect(p.len == 5000);
    for (0..100) |i| try std.testing.expectEqual(@as(u8, @truncate(i)), p[i]);
    a.free(p);
}
