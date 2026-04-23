const std = @import("std");

/// Allocator wrapper that rounds every allocation size up to a multiple of
/// `granularity` bytes.  When all allocations end on a common boundary a
/// FixedBufferAllocator can always unwind them in LIFO order without leaving
/// alignment-padding gaps that prevent resize().
pub const RoundedAllocator = struct {
    backing: std.mem.Allocator,

    const granularity = 32;

    fn round(n: usize) usize {
        return std.mem.alignForward(usize, n, granularity);
    }

    pub fn allocator(self: *RoundedAllocator) std.mem.Allocator {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = std.mem.Allocator.VTable{
        .alloc = alloc,
        .resize = resize,
        .remap = remap,
        .free = free,
    };

    fn alloc(ctx: *anyopaque, n: usize, alignment: std.mem.Alignment, ret_addr: usize) ?[*]u8 {
        const self: *RoundedAllocator = @ptrCast(@alignCast(ctx));
        return self.backing.vtable.alloc(self.backing.ptr, round(n), alignment, ret_addr);
    }

    fn resize(ctx: *anyopaque, buf: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) bool {
        const self: *RoundedAllocator = @ptrCast(@alignCast(ctx));
        return self.backing.vtable.resize(self.backing.ptr, buf.ptr[0..round(buf.len)], alignment, round(new_len), ret_addr);
    }

    fn remap(ctx: *anyopaque, buf: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) ?[*]u8 {
        const self: *RoundedAllocator = @ptrCast(@alignCast(ctx));
        return self.backing.vtable.remap(self.backing.ptr, buf.ptr[0..round(buf.len)], alignment, round(new_len), ret_addr);
    }

    fn free(ctx: *anyopaque, buf: []u8, alignment: std.mem.Alignment, ret_addr: usize) void {
        const self: *RoundedAllocator = @ptrCast(@alignCast(ctx));
        self.backing.vtable.free(self.backing.ptr, buf.ptr[0..round(buf.len)], alignment, ret_addr);
    }
};
