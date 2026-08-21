const std = @import("std");
const Blockchain = @import("blockchain.zig").Blockchain;
const rlpx = @import("../devp2p/rlpx.zig");
const eth = @import("../devp2p/eth.zig");
const snap = @import("../devp2p/snap.zig");
const types = @import("../types.zig");
const rlp = @import("rlp");
const FreeList = @import("../free_list.zig").FreeList;
const List = @import("../free_list.zig").List;
const max_inflight_requests = 100;

fn Request(comptime msg: type) type {
    return struct {
        id: u64,
        peer: rlpx.Server.PeerId,
        msg: msg,
        deadline: std.Io.Timestamp,
    };
}

pub const Downloader = struct {
    const Self = @This();

    io: std.Io,
    allocator: std.mem.Allocator,
    bc: *Blockchain,

    eth_provider: *eth.Provider,
    free_eth_requests: FreeList(Request(eth.Message)),
    inflight_eth_requests: List(Request(eth.Message)),

    snap_provider: *snap.Provider,
    free_snap_requests: FreeList(Request(snap.Message)),
    inflight_snap_requests: List(Request(snap.Message)),

    sync_target: ?struct {
        number: u64,
        hash: [32]u8,

        cutoff_number: u64, // last header to fetch, inclusive
        cutoff_hash: [32]u8,
    },
    state: union(enum) {
        idle,
        active: struct {
            requested_header_head: u64,
            requested_header_tail: u64,
        },
    },

    pub fn init(
        io: std.Io,
        allocator: std.mem.Allocator,
        bc: *Blockchain,
        eth_provider: *eth.Provider,
        snap_provider: *snap.Provider,
    ) !Self {
        return .{
            .io = io,
            .allocator = allocator,
            .bc = bc,
            .eth_provider = eth_provider,
            .free_eth_requests = try .init(allocator, max_inflight_requests),
            .inflight_eth_requests = .{},
            .snap_provider = snap_provider,
            .free_snap_requests = try .init(allocator, max_inflight_requests),
            .inflight_snap_requests = .{},
            .sync_target = null,
            .state = .idle,
        };
    }

    pub fn run(self: *Self) !void {
        const tag = enum(u8) { eth, snap, tick };
        const msg = union(tag) {
            eth: @typeInfo(@TypeOf(eth.Provider.next)).@"fn".return_type.?,
            snap: @typeInfo(@TypeOf(snap.Provider.next)).@"fn".return_type.?,
            tick: @typeInfo(@TypeOf(std.Io.sleep)).@"fn".return_type.?,
        };

        var buf: [3]msg = undefined;
        var select: std.Io.Select(msg) = .init(self.io, &buf);

        select.async(.eth, eth.Provider.next, .{ self.eth_provider, self.io, self.allocator, self.allocator });
        select.async(.snap, snap.Provider.next, .{ self.snap_provider, self.io, self.allocator, self.allocator });
        select.async(.tick, std.Io.sleep, .{ self.io, .fromSeconds(1), .real });

        while (true) {
            switch (select.await() catch |e| return e) {
                .eth => |res| {
                    const received_message = try res;
                    defer self.allocator.free(received_message.read.payload);
                    try self.handleEth(received_message.msg, received_message.read.peer);
                    select.async(.eth, eth.Provider.next, .{ self.eth_provider, self.io, self.allocator, self.allocator });
                },
                .snap => |res| {
                    const received_message = try res;
                    defer self.allocator.free(received_message.read.payload);
                    try self.handleSnap(received_message.msg, received_message.read.peer);
                    select.async(.snap, snap.Provider.next, .{ self.snap_provider, self.io, self.allocator, self.allocator });
                },
                .tick => {
                    try self.handleTick();
                    select.async(.tick, std.Io.sleep, .{ self.io, .fromSeconds(1), .real });
                },
            }
        }
    }

    fn handleTick(self: *Self) !void {
        if (self.sync_target != null) {
            switch (self.state) {
                .idle => {
                    self.state = .{
                        .active = .{
                            .requested_header_head = 0,
                            .requested_header_tail = std.math.maxInt(u64),
                        },
                    };
                },
                .active => try self.advanceDownload(),
            }
        }
        try self.checkEthRequestTimeouts();
    }

    fn checkEthRequestTimeouts(
        self: *Self,
    ) !void {
        var current_node = self.inflight_eth_requests.inner.first;

        const now = std.Io.Clock.now(.real, self.io).toMilliseconds();
        while (current_node) |node| {
            const next_node = node.next;
            const request: *List(Request(eth.Message)).Node = @alignCast(@fieldParentPtr("node", node));

            if (request.elem.deadline.toMilliseconds() < now) {
                request.elem.peer = self.eth_provider.sendToRandomPeer(request.elem.msg) catch continue;
                request.elem.deadline = std.Io.Clock.now(.real, self.io).addDuration(.fromSeconds(3));
            }

            current_node = next_node;
        }
    }

    fn handleEth(self: *Self, msg: eth.Message, peer: rlpx.Server.PeerId) !void {
        switch (msg) {
            .status => |status| {
                try self.updateTarget(status.latest_block, status.latest_block_hash);
            },
            .block_range_update => |update| {
                try self.updateTarget(update.latest_block, update.latest_block_hash);
            },
            .block_headers => |headers| {
                if (matchRequest(eth.Message, &self.inflight_eth_requests, peer, headers.request_id, .get_block_headers)) |req|
                    try self.handleHeaders(req, headers);
            },
            else => {},
        }
    }

    fn updateTarget(self: *Self, number: u64, hash: [32]u8) !void {
        const head = try self.bc.head();
        if (head.number >= number) return;
        if (self.sync_target) |cur_target| {
            if (cur_target.number >= number) return;
        }

        self.sync_target = .{
            .hash = hash,
            .number = number,
            .cutoff_number = head.number,
            .cutoff_hash = head.hash,
        };
    }

    fn advanceDownload(self: *Self) !void {
        if (self.sync_target == null) return;
        const target = self.sync_target.?;

        var status = &self.state.active;
        while (status.requested_header_tail > target.cutoff_number) {
            const origin: eth.HashOrNumber, const origin_num = if (status.requested_header_tail == std.math.maxInt(u64))
                .{ .{ .hash = target.hash }, target.number }
            else
                .{ .{ .number = status.requested_header_tail }, status.requested_header_tail };
            const batch_size = @as(u64, @min(1023, origin_num - target.cutoff_number)) + 1;
            requestHeaders(self, origin, batch_size) catch {
                break;
            };
            status.requested_header_tail = (origin_num + 1) - batch_size;
            if (status.requested_header_head < origin_num)
                status.requested_header_head = origin_num;
        }

        if (status.requested_header_head < target.number) {
            // target moved, fill the gap from new head to old head
            requestHeaders(
                self,
                .{ .hash = target.hash },
                target.number - status.requested_header_head,
            ) catch return;
            status.requested_header_head = target.number;
        }
    }

    fn requestHeaders(self: *Self, origin: eth.HashOrNumber, amount: u64) !void {
        const id = self.eth_provider.nextRequestId();
        try self.sendEthRequest(id, .{ .get_block_headers = .{
            .id = id,
            .query = .{
                .origin = origin,
                .amount = amount,
                .skip = 0,
                .reverse = true,
            },
        } });
    }

    fn handleHeaders(self: *Self, matched_request: *Request(eth.Message), response: eth.BlockHeaders) !void {
        const headers_request = matched_request.msg.get_block_headers;

        const hashes, const headers = self.validateHeadersResponse(headers_request, response) catch {
            self.free_eth_requests.list().push(matched_request);
            try self.requestHeaders(headers_request.query.origin, headers_request.query.amount);
            return;
        };
        defer {
            self.allocator.free(hashes);
            self.allocator.free(headers);
        }

        var followup_request: ?@TypeOf(headers_request.query) = null;
        if (headers.len > 0) {
            const invalidated_range = try self.persistDownloadedHeaderChain(
                headers,
                hashes,
                headers_request.query.amount,
            );
            if (invalidated_range) |range| {
                followup_request = .{
                    .origin = .{ .hash = range.origin },
                    .amount = range.amount,
                };
            } else if (headers_request.query.amount > headers.len) {
                followup_request = .{
                    .origin = .{ .hash = headers[headers.len - 1].parent_hash },
                    .amount = headers_request.query.amount - hashes.len,
                };
            }
        } else followup_request = headers_request.query;

        self.free_eth_requests.list().push(matched_request);
        if (followup_request) |followup| {
            try self.requestHeaders(
                followup.origin,
                followup.amount,
            );
        } else {
            try self.advanceDownload();
        }

        try self.checkHeaderDownloadComplete();
    }

    fn validateHeadersResponse(
        self: *Self,
        request: eth.GetBlockHeaders,
        response: eth.BlockHeaders,
    ) !struct { [][32]u8, []types.BlockHeader } {
        if (response.data.len == 0) return .{ &[_][32]u8{}, &[_]types.BlockHeader{} };

        var headers: []types.BlockHeader = try self.allocator.alloc(types.BlockHeader, response.data.len);
        errdefer self.allocator.free(headers);
        var hashes: [][32]u8 = try self.allocator.alloc([32]u8, response.data.len);
        errdefer self.allocator.free(hashes);
        for (response.data, 0..) |header_rlp, index| {
            const canon_index = if (request.query.reverse) response.data.len - index - 1 else index;
            _ = try rlp.deserialize(types.BlockHeader, self.allocator, header_rlp.value, &headers[canon_index]);
            std.crypto.hash.sha3.Keccak256.hash(header_rlp.value, &hashes[canon_index], .{});
        }

        for (1..headers.len) |i| {
            if (!std.meta.eql(hashes[i - 1], headers[i].parent_hash)) {
                return error.InvalidHeaderChain;
            }
        }

        switch (request.query.origin) {
            .hash => |expected_hash| {
                if (!std.meta.eql(hashes[hashes.len - 1], expected_hash)) return error.UnexpectedOriginHeader;
            },
            .number => |expected_number| {
                if (expected_number != headers[hashes.len - 1].number) return error.UnexpectedOriginHeader;
            },
        }

        return .{ hashes, headers };
    }

    fn persistDownloadedHeaderChain(
        self: *Self,
        headers: []types.BlockHeader,
        hashes: [][32]u8,
        original_requested_amount: u64,
    ) !?struct { origin: [32]u8, amount: u64 } {
        if (try self.readDownladedHeader(headers[headers.len - 1].number + 1)) |child_header| {
            if (!std.meta.eql(child_header.parent_hash, hashes[headers.len - 1])) {
                return .{ .origin = child_header.parent_hash, .amount = original_requested_amount };
            }
        }

        if (headers[0].number > 0) {
            if (try self.readDownladedHeader(headers[0].number - 1)) |parent_header| {
                if (!std.meta.eql(headers[0].parent_hash, parent_header.hash())) {
                    var invalidated_count: usize = 1;
                    while (try self.readDownladedHeader(headers[0].number - 1 - invalidated_count)) |invalidated_header| {
                        invalidated_count += 1;
                        if (invalidated_header.number == 0) break;
                    }
                    try self.clearDownloadedHeader(headers[0].number - 1);
                    try self.clearDownloadedHeader(headers[0].number - invalidated_count);
                    return .{ .origin = headers[0].parent_hash, .amount = invalidated_count };
                }
            }
        }

        const offset = headers[0].number * @sizeOf(types.BlockHeader);
        const bytes: [*]u8 = @ptrCast(headers.ptr);
        const size = @sizeOf(types.BlockHeader) * headers.len;

        const file = try self.bc.file_storage.openFile(self.io, "downloaded_headers.dat");
        defer file.release();
        try file.value.file.writePositionalAll(self.io, bytes[0..size], offset);
        return null;
    }

    fn readDownladedHeader(self: *Self, number: u64) !?types.BlockHeader {
        const file = try self.bc.file_storage.openFile(self.io, "downloaded_headers.dat");
        defer file.release();

        const offset = number * @sizeOf(types.BlockHeader);
        var header: types.BlockHeader = undefined;
        const buf: [*]u8 = @ptrCast(&header);

        if (try file.value.file.readPositionalAll(self.io, buf[0..@sizeOf(types.BlockHeader)], offset) == @sizeOf(types.BlockHeader)) {
            if (!std.meta.eql(header, std.mem.zeroes(types.BlockHeader))) {
                return header;
            }
        }
        return null;
    }

    fn clearDownloadedHeader(self: *Self, number: u64) !void {
        const offset = number * @sizeOf(types.BlockHeader);
        var header: types.BlockHeader = std.mem.zeroes(types.BlockHeader);
        const bytes: [*]u8 = @ptrCast(&header);

        const file = try self.bc.file_storage.openFile(self.io, "downloaded_headers.dat");
        defer file.release();
        try file.value.file.writePositionalAll(self.io, bytes[0..@sizeOf(types.BlockHeader)], offset);
    }

    fn clearDownloadedHeaders(self: *Self) !void {
        const file = try self.bc.file_storage.openFile(self.io, "downloaded_headers.dat");
        defer file.release();
        try file.value.file.setLength(self.io, 0);
    }

    fn checkHeaderDownloadComplete(self: *Self) !void {
        if (self.state.active.requested_header_head != self.sync_target.?.number or
            self.state.active.requested_header_tail != self.sync_target.?.cutoff_number)
            return;

        var current_node = self.inflight_eth_requests.inner.first;
        while (current_node) |node| {
            const next_node = node.next;
            const request: *List(Request(eth.Message)).Node = @alignCast(@fieldParentPtr("node", node));
            if (request.elem.msg == .get_block_headers) return;
            current_node = next_node;
        }

        const head = try self.bc.head();
        for (head.number + 1..self.state.active.requested_header_head + 1) |number| {
            const header = (try self.readDownladedHeader(number)).?;
            try self.bc.appendHeader(&header);
        }

        try self.clearDownloadedHeaders();
        self.state = .idle;
        self.sync_target = null;
    }

    fn handleSnap(_: *Self, _: snap.Message, _: rlpx.Server.PeerId) !void {}

    fn sendEthRequest(self: *Self, id: u64, msg: eth.Message) !void {
        const req = self.free_eth_requests.list().pop() orelse return error.ReachedConcurrentRequestsLimit;
        errdefer self.free_eth_requests.list().push(req);
        const peer = try self.eth_provider.sendToRandomPeer(msg);
        req.* = .{
            .id = id,
            .peer = peer,
            .msg = msg,
            .deadline = std.Io.Clock.now(.real, self.io).addDuration(.fromSeconds(3)),
        };
        self.inflight_eth_requests.push(req);
    }

    fn matchRequest(
        comptime Message: type,
        list: *List(Request(Message)),
        peer: rlpx.Server.PeerId,
        id: u64,
        request_tag: std.meta.Tag(Message),
    ) ?*Request(Message) {
        var current_node = list.inner.first;

        while (current_node) |node| {
            const next_node = node.next;
            const request: *List(Request(Message)).Node = @alignCast(@fieldParentPtr("node", node));

            if (request.elem.id == id and std.meta.eql(peer, request.elem.peer) and std.meta.eql(request_tag, request.elem.msg)) {
                list.inner.remove(node);
                node.next = null;
                node.prev = null;
                return &request.elem;
            }

            current_node = next_node;
        }
        return null;
    }
};
