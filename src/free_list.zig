const std = @import("std");

pub fn List(comptime T: type) type {
    return struct {
        pub const Node = struct {
            elem: T,
            node: std.DoublyLinkedList.Node,
        };

        storage: []Node = &[_]Node{},
        inner: std.DoublyLinkedList = .{},

        pub fn init(allocator: std.mem.Allocator, n: usize) !List(T) {
            const storage = try allocator.alloc(Node, n);
            var ll: std.DoublyLinkedList = .{};
            for (storage) |*node|
                ll.append(&node.node);
            return .{
                .storage = storage,
                .inner = ll,
            };
        }

        pub fn deinit(self: *List(T), allocator: std.mem.Allocator) void {
            allocator.free(self.storage);
        }

        pub fn pop(self: *List(T)) ?*T {
            const list_node = self.inner.popFirst() orelse return null;
            const node: *Node = @alignCast(@fieldParentPtr("node", list_node));
            return &node.elem;
        }

        pub fn push(self: *List(T), elem: *T) void {
            const node: *Node = @alignCast(@fieldParentPtr("elem", elem));
            self.inner.append(&node.node);
        }

        pub fn prepend(self: *List(T), elem: *T) void {
            const node: *Node = @alignCast(@fieldParentPtr("elem", elem));
            self.inner.prepend(&node.node);
        }

        pub fn empty(self: *List(T)) bool {
            return self.inner.first == null;
        }
    };
}
