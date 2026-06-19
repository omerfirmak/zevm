const std = @import("std");
const zkvm = @import("zkvm");
const verify_ssz = @import("guest.zig").verify_ssz;

extern const _evm_heap_bottom: u8;
extern const _evm_heap_size: u8;

comptime {
    @export(&zkvmMain, .{ .name = "main" });
}

fn zkvmMain() callconv(.c) void {
    const heap_ptr: [*]u8 = @ptrCast(@constCast(&_evm_heap_bottom));
    const heap_len: usize = @intFromPtr(&_evm_heap_size);
    var fba = std.heap.FixedBufferAllocator.init(heap_ptr[0..heap_len]);

    var input_ptr: [*c]const u8 = undefined;
    var input_len: usize = undefined;
    zkvm.read_input(&input_ptr, &input_len);

    const output = verify_ssz(fba.allocator(), input_ptr[0..input_len]) catch
        @panic("verify_ssz failed");
    zkvm.write_output(output.ptr, output.len);
}
