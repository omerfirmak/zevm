// Copyright (c) 2025-2026 zevm authors
// SPDX-License-Identifier: MIT OR Apache-2.0

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

        pub fn initDefault(allocator: std.mem.Allocator, n: usize, default: T) !List(T) {
            const list: List(T) = try .init(allocator, n);
            for (list.storage) |*node|
                node.elem = default;
            return list;
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

        pub fn remove(self: *List(T), elem: *T) void {
            const node: *Node = @alignCast(@fieldParentPtr("elem", elem));
            self.inner.remove(&node.node);
        }

        pub fn insertSorted(self: *List(T), elem: *T, comptime lessThan: fn (void, T, T) bool) void {
            const node: *Node = @alignCast(@fieldParentPtr("elem", elem));
            var current_node = self.inner.last;
            while (current_node) |list_node| : (current_node = list_node.prev) {
                const current: *Node = @alignCast(@fieldParentPtr("node", list_node));
                if (!lessThan({}, elem.*, current.elem)) return self.inner.insertAfter(list_node, &node.node);
            }
            self.inner.prepend(&node.node);
        }

        pub fn empty(self: *List(T)) bool {
            return self.inner.first == null;
        }

        pub fn head(self: *List(T)) *T {
            const node: *Node = @alignCast(@fieldParentPtr("node", self.inner.first.?));
            return &node.elem;
        }

        pub fn tail(self: *List(T)) *T {
            const node: *Node = @alignCast(@fieldParentPtr("node", self.inner.last.?));
            return &node.elem;
        }
    };
}
