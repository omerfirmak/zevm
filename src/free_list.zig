const std = @import("std");

pub fn List(comptime T: type) type {
    return struct {
        pub const Node = struct {
            elem: T,
            node: std.DoublyLinkedList.Node,
        };

        inner: std.DoublyLinkedList = .{},

        pub fn pop(self: *List(T)) ?*T {
            const list_node = self.inner.popFirst() orelse return null;
            const node: *Node = @alignCast(@fieldParentPtr("node", list_node));
            return &node.elem;
        }

        pub fn push(self: *List(T), elem: *T) void {
            const node: *Node = @alignCast(@fieldParentPtr("elem", elem));
            self.inner.append(&node.node);
        }

        pub fn empty(self: *List(T)) bool {
            return self.inner.first == null;
        }
    };
}

pub fn FreeList(comptime T: type) type {
    return struct {
        const Node = List(T).Node;

        storage: []Node,
        ll: List(T),

        pub fn init(allocator: std.mem.Allocator, n: usize) !FreeList(T) {
            const storage = try allocator.alloc(Node, n);
            var ll: std.DoublyLinkedList = .{};
            for (storage) |*node|
                ll.append(&node.node);
            return .{
                .storage = storage,
                .ll = .{ .inner = ll },
            };
        }

        pub fn deinit(self: *FreeList(T), allocator: std.mem.Allocator) void {
            allocator.free(self.storage);
        }

        pub fn getAt(self: *FreeList(T), index: usize) *T {
            return &self.storage[index].elem;
        }

        pub fn indexOf(self: *FreeList(T), elem: *const T) usize {
            const node: *const Node = @alignCast(@fieldParentPtr("elem", elem));
            return node - self.storage.ptr;
        }

        pub fn list(self: *FreeList(T)) *List(T) {
            return &self.ll;
        }
    };
}

test "freelist" {
    var fl = try FreeList(u8).init(std.testing.allocator, 2);
    defer fl.deinit(std.testing.allocator);

    const first = fl.list().pop();
    try std.testing.expect(first != null);
    try std.testing.expectEqual(0, fl.indexOf(first.?));
    const second = fl.list().pop();
    try std.testing.expect(first != null);
    try std.testing.expectEqual(1, fl.indexOf(second.?));

    const none = fl.list().pop();
    try std.testing.expect(none == null);

    fl.list().push(first.?);
    const first_again = fl.list().pop();
    try std.testing.expect(first_again != null);
    try std.testing.expectEqual(0, fl.indexOf(first_again.?));
}
