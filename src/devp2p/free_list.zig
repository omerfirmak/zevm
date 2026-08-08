const std = @import("std");

pub fn FreeList(comptime T: type) type {
    return struct {
        const Node = struct {
            elem: T,
            node: std.SinglyLinkedList.Node,
        };

        storage: []Node,
        list: std.SinglyLinkedList,

        pub fn init(allocator: std.mem.Allocator, n: usize) !FreeList(T) {
            const storage = try allocator.alloc(Node, n);
            var list: std.SinglyLinkedList = .{};
            for (storage) |*node|
                list.prepend(&node.node);
            return .{
                .storage = storage,
                .list = list,
            };
        }

        pub fn deinit(self: *FreeList(T), allocator: std.mem.Allocator) void {
            allocator.free(self.storage);
        }

        pub fn pop(self: *FreeList(T)) ?*T {
            const list_node = self.list.popFirst() orelse return null;
            const node: *Node = @fieldParentPtr("node", list_node);
            return &node.elem;
        }

        pub fn push(self: *FreeList(T), elem: *T) void {
            const node: *Node = @alignCast(@fieldParentPtr("elem", elem));
            self.list.prepend(&node.node);
        }

        pub fn getAt(self: *FreeList(T), index: usize) *T {
            return &self.storage[index].elem;
        }

        pub fn indexOf(self: *FreeList(T), elem: *const T) usize {
            const node: *const Node = @alignCast(@fieldParentPtr("elem", elem));
            return node - self.storage.ptr;
        }

        pub fn empty(self: *FreeList(T)) bool {
            return self.list.first == null;
        }
    };
}

test "freelist" {
    var fl = try FreeList(u8).init(std.testing.allocator, 2);
    defer fl.deinit(std.testing.allocator);

    const first = fl.pop();
    try std.testing.expect(first != null);
    try std.testing.expectEqual(1, fl.indexOf(first.?));
    const second = fl.pop();
    try std.testing.expect(first != null);
    try std.testing.expectEqual(0, fl.indexOf(second.?));

    const none = fl.pop();
    try std.testing.expect(none == null);

    fl.push(first.?);
    const first_again = fl.pop();
    try std.testing.expect(first_again != null);
    try std.testing.expectEqual(1, fl.indexOf(first_again.?));
}
