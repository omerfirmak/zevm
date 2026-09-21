const std = @import("std");
const Blockchain = @import("blockchain.zig").Blockchain;
const rlpx = @import("../devp2p/rlpx.zig");
const eth = @import("../devp2p/eth.zig");
const snap = @import("../devp2p/snap.zig");
const types = @import("../types.zig");
const rlp = @import("rlp");
const trie = @import("../trie/trie.zig");

const verifyRangeProof = @import("../trie/range_proof.zig").verifyRangeProof;
const EthDb = @import("../db/eth.zig").Eth;
const List = @import("../free_list.zig").List;
const max_inflight_requests = 100;
const header_persist_chunk = 1024;

const log = std.log.scoped(.downloader);

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
    const PeerRange = struct {
        id: rlpx.Server.PeerId,
        range: eth.BlockRangeUpdate,
    };

    io: std.Io,
    allocator: std.mem.Allocator,
    bc: *Blockchain,
    eth_db: *EthDb,

    peer_ranges: []?PeerRange,

    eth_arena: std.heap.ArenaAllocator,
    eth_provider: *eth.Provider,
    free_eth_requests: List(Request(eth.Message)),
    inflight_eth_requests: List(Request(eth.Message)),

    snap_arena: std.heap.ArenaAllocator,
    snap_provider: *snap.Provider,
    free_snap_requests: List(Request(snap.Message)),
    inflight_snap_requests: List(Request(snap.Message)),

    sync_target: ?struct {
        number: u64,
        hash: [32]u8,

        cutoff_number: u64, // last header to fetch, inclusive
        cutoff_hash: [32]u8,
    },
    state: union(enum) {
        idle,
        initial: struct {
            requested_header_head: u64,
            requested_header_tail: u64,

            pivot: ?types.BlockHeader,
            previous_pivot: ?types.BlockHeader,
        },
    },

    pub fn init(
        io: std.Io,
        allocator: std.mem.Allocator,
        bc: *Blockchain,
        eth_db: *EthDb,
        eth_provider: *eth.Provider,
        snap_provider: *snap.Provider,
    ) !Self {
        const peer_ranges = try allocator.alloc(?PeerRange, eth_provider.peers.len);
        @memset(peer_ranges, null);

        return .{
            .io = io,
            .allocator = allocator,
            .bc = bc,
            .eth_db = eth_db,
            .eth_arena = .init(allocator),
            .eth_provider = eth_provider,
            .free_eth_requests = try .init(allocator, max_inflight_requests),
            .inflight_eth_requests = .{},
            .snap_arena = .init(allocator),
            .snap_provider = snap_provider,
            .free_snap_requests = try .init(allocator, max_inflight_requests),
            .inflight_snap_requests = .{},
            .sync_target = null,
            .state = .idle,
            .peer_ranges = peer_ranges,
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

        select.async(.eth, eth.Provider.next, .{ self.eth_provider, self.io, self.eth_arena.allocator(), self.allocator });
        select.async(.snap, snap.Provider.next, .{ self.snap_provider, self.io, self.snap_arena.allocator(), self.allocator });
        select.async(.tick, std.Io.sleep, .{ self.io, .fromSeconds(1), .real });

        while (true) {
            switch (select.await() catch |e| return e) {
                .eth => |res| {
                    defer {
                        _ = self.eth_arena.reset(.retain_capacity);
                        select.async(.eth, eth.Provider.next, .{ self.eth_provider, self.io, self.eth_arena.allocator(), self.allocator });
                    }
                    const received_message = res catch continue;
                    defer self.allocator.free(received_message.read.payload);
                    try self.handleEth(received_message.msg, received_message.read.peer);
                },
                .snap => |res| {
                    defer {
                        _ = self.snap_arena.reset(.retain_capacity);
                        select.async(.snap, snap.Provider.next, .{ self.snap_provider, self.io, self.snap_arena.allocator(), self.allocator });
                    }
                    const received_message = res catch continue;
                    defer self.allocator.free(received_message.read.payload);
                    try self.handleSnap(received_message.msg, received_message.read.peer);
                },
                .tick => {
                    defer select.async(.tick, std.Io.sleep, .{ self.io, .fromSeconds(1), .real });
                    try self.handleTick();
                },
            }
        }
    }

    fn handleTick(self: *Self) !void {
        switch (self.state) {
            .initial => {
                try self.advanceDownload();
                try self.updatePivot();
            },
            else => {},
        }
        try self.checkEthRequestTimeouts();
        try self.checkSnapRequestTimeouts();
    }

    fn checkEthRequestTimeouts(self: *Self) !void {
        var current_node = self.inflight_eth_requests.inner.first;

        const now = std.Io.Clock.now(.real, self.io).toMilliseconds();
        while (current_node) |node| {
            const next_node = node.next;
            const request: *List(Request(eth.Message)).Node = @alignCast(@fieldParentPtr("node", node));

            if (request.elem.deadline.toMilliseconds() < now) {
                if (self.sendEthMessage(request.elem.msg)) |peer_id| {
                    request.elem.peer = peer_id;
                    request.elem.deadline = std.Io.Clock.now(.real, self.io).addDuration(.fromSeconds(3));
                } else |_| {}
            }

            current_node = next_node;
        }
    }

    fn checkSnapRequestTimeouts(self: *Self) !void {
        var current_node = self.inflight_snap_requests.inner.first;

        const now = std.Io.Clock.now(.real, self.io).toMilliseconds();
        while (current_node) |node| {
            const next_node = node.next;
            const request: *List(Request(snap.Message)).Node = @alignCast(@fieldParentPtr("node", node));

            if (request.elem.deadline.toMilliseconds() < now) {
                if (self.sendSnapMessage(request.elem.msg)) |peer_id| {
                    request.elem.peer = peer_id;
                    request.elem.deadline = std.Io.Clock.now(.real, self.io).addDuration(.fromSeconds(3));
                } else |_| {}
            }

            current_node = next_node;
        }
    }

    fn handleEth(self: *Self, msg: eth.Message, peer: rlpx.Server.PeerId) !void {
        switch (msg) {
            .status => |status| {
                try self.updateTarget(status.latest_block, status.latest_block_hash);
                self.peer_ranges[peer.peer_index] = .{ .id = peer, .range = .{
                    .earliest_block = status.earliest_block,
                    .latest_block = status.latest_block,
                    .latest_block_hash = status.latest_block_hash,
                } };
            },
            .block_range_update => |update| {
                try self.updateTarget(update.latest_block, update.latest_block_hash);
                self.peer_ranges[peer.peer_index] = .{ .id = peer, .range = update };
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

        if (head.number == 0 and self.state == .idle) {
            self.state = .{ .initial = .{
                .requested_header_head = 0,
                .requested_header_tail = std.math.maxInt(u64),
                .pivot = null,
                .previous_pivot = null,
            } };
        }
        self.sync_target = .{
            .hash = hash,
            .number = number,
            .cutoff_number = head.number,
            .cutoff_hash = head.hash,
        };

        try self.updatePivot();
    }

    fn pickEthPeer(self: *Self, msg: eth.Message) !rlpx.Server.PeerId {
        switch (msg) {
            .get_block_headers => |header_req| switch (header_req.query.origin) {
                .number => |number| return self.eth_provider.pickRandomPeer(HeightFilter.init(number, self)),
                else => {},
            },
            else => {},
        }
        return self.eth_provider.pickRandomPeer({});
    }

    fn sendEthMessage(self: *Self, msg: eth.Message) !rlpx.Server.PeerId {
        const peer = try self.pickEthPeer(msg);
        try self.eth_provider.send(peer, msg);
        return peer;
    }

    fn advanceDownload(self: *Self) !void {
        if (self.sync_target == null) return;
        const target = self.sync_target.?;

        var status = &self.state.initial;
        if (status.requested_header_tail != std.math.maxInt(u64) and status.requested_header_head < target.number) {
            // target moved, fill the gap from new head to old head
            requestHeaders(
                self,
                .{ .hash = target.hash },
                target.number - status.requested_header_head,
            ) catch return;
            status.requested_header_head = target.number;
        }

        while (status.requested_header_tail > target.cutoff_number) {
            const origin: eth.HashOrNumber, const origin_num = if (status.requested_header_tail == std.math.maxInt(u64))
                .{ .{ .hash = target.hash }, target.number }
            else
                .{ .{ .number = status.requested_header_tail }, status.requested_header_tail };
            const batch_size = @as(u64, @min(1023, origin_num - target.cutoff_number)) + 1;
            requestHeaders(self, origin, batch_size) catch {
                return;
            };
            status.requested_header_tail = (origin_num + 1) - batch_size;
            if (status.requested_header_head < origin_num)
                status.requested_header_head = origin_num;
        }
    }

    fn headerQuery(id: u64, origin: eth.HashOrNumber, amount: u64) eth.Message {
        return .{ .get_block_headers = .{ .id = id, .query = .{
            .origin = origin,
            .amount = amount,
            .skip = 0,
            .reverse = true,
        } } };
    }

    fn requestHeaders(self: *Self, origin: eth.HashOrNumber, amount: u64) !void {
        const id = self.eth_provider.nextRequestId();

        const req = self.free_eth_requests.pop() orelse return error.ReachedConcurrentRequestsLimit;
        errdefer self.free_eth_requests.push(req);

        const msg = headerQuery(id, origin, amount);
        const peer = try self.sendEthMessage(msg);

        req.* = .{
            .id = id,
            .peer = peer,
            .msg = msg,
            .deadline = std.Io.Clock.now(.real, self.io).addDuration(.fromSeconds(3)),
        };
        self.inflight_eth_requests.push(req);

        log.debug("requesting headers origin {} amount {}", .{ origin, amount });
    }

    fn reissueHeaderRequest(self: *Self, request: *Request(eth.Message), origin: eth.HashOrNumber, amount: u64) void {
        const id = self.eth_provider.nextRequestId();
        request.id = id;
        request.msg = headerQuery(id, origin, amount);
        if (self.sendEthMessage(request.msg)) |peer| {
            request.peer = peer;
            request.deadline = std.Io.Clock.now(.real, self.io).addDuration(.fromSeconds(3));
        } else |e| {
            log.debug("reissue for origin {} amount {} deferred: {t}", .{ origin, amount, e });
            request.deadline = std.Io.Clock.now(.real, self.io);
        }
        self.inflight_eth_requests.push(request);
    }

    fn handleHeaders(self: *Self, matched_request: *Request(eth.Message), response: eth.BlockHeaders) !void {
        const headers_request = matched_request.msg.get_block_headers;

        const hashes, const headers = self.validateHeadersResponse(headers_request, response) catch |e| {
            log.debug("header validation failed for origin {} amount {}: {t}", .{ headers_request.query.origin, headers_request.query.amount, e });
            self.reissueHeaderRequest(matched_request, headers_request.query.origin, headers_request.query.amount);
            return;
        };

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
            } else if (headers_request.query.amount > headers.len and headers[0].number > 0) {
                followup_request = .{
                    .origin = .{ .hash = headers[0].parent_hash },
                    .amount = headers_request.query.amount - headers.len,
                };
            }
            log.debug("validated header range start {} end {} invalidated {any}", .{ headers[0].number, headers[0].number + headers.len - 1, invalidated_range });
        } else followup_request = headers_request.query;

        if (followup_request) |followup| {
            self.reissueHeaderRequest(matched_request, followup.origin, followup.amount);
        } else {
            self.free_eth_requests.push(matched_request);
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

        const allocator = self.eth_arena.allocator();
        var headers: []types.BlockHeader = try allocator.alloc(types.BlockHeader, response.data.len);
        var hashes: [][32]u8 = try allocator.alloc([32]u8, response.data.len);
        for (response.data, 0..) |header_rlp, index| {
            const canon_index = if (request.query.reverse) response.data.len - index - 1 else index;
            _ = try rlp.deserialize(types.BlockHeader, allocator, header_rlp.value, &headers[canon_index]);
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

        const offset = headers[0].number * @sizeOf(types.BlockHeader);
        const bytes: [*]u8 = @ptrCast(headers.ptr);
        const size = @sizeOf(types.BlockHeader) * headers.len;

        const file = try self.bc.file_storage.openFile(self.io, "downloaded_headers.dat");
        defer file.release();
        try file.value.file.writePositionalAll(self.io, bytes[0..size], offset);

        if (headers[0].number > 0) {
            if (try self.readDownladedHeader(headers[0].number - 1)) |parent_header| {
                if (!std.meta.eql(headers[0].parent_hash, parent_header.hash())) {
                    var invalidated_count: usize = 1;
                    while (try self.readDownladedHeader(headers[0].number - 1 - invalidated_count)) |invalidated_header| {
                        invalidated_count += 1;
                        if (invalidated_header.number == 0 or invalidated_count == header_persist_chunk) break;
                    }
                    try self.clearDownloadedHeader(headers[0].number - 1);
                    try self.clearDownloadedHeader(headers[0].number - invalidated_count);
                    return .{ .origin = headers[0].parent_hash, .amount = invalidated_count };
                }
            }
        }

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

    fn readDownladedHeaders(self: *Self, allocator: std.mem.Allocator, start: u64, count: u64) ![]types.BlockHeader {
        const file = try self.bc.file_storage.openFile(self.io, "downloaded_headers.dat");
        defer file.release();

        const headers = try allocator.alloc(types.BlockHeader, count);
        errdefer allocator.free(headers);

        const offset = start * @sizeOf(types.BlockHeader);
        const bytes: [*]u8 = @ptrCast(headers.ptr);
        const size = count * @sizeOf(types.BlockHeader);

        if (try file.value.file.readPositionalAll(self.io, bytes[0..size], offset) != size) return error.MissingDownloadedHeader;
        for (headers) |*header| {
            if (std.meta.eql(header.*, std.mem.zeroes(types.BlockHeader))) return error.MissingDownloadedHeader;
        }

        return headers;
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
        if (self.state.initial.requested_header_head < self.sync_target.?.number or
            self.state.initial.requested_header_tail > self.sync_target.?.cutoff_number)
            return;

        var current_node = self.inflight_eth_requests.inner.first;
        while (current_node) |node| {
            const next_node = node.next;
            const request: *List(Request(eth.Message)).Node = @alignCast(@fieldParentPtr("node", node));
            if (request.elem.msg == .get_block_headers) return;
            current_node = next_node;
        }

        const head = try self.bc.head();
        log.debug("persisting headers start {} end {}", .{
            head.number + 1,
            self.sync_target.?.number,
        });

        const first = head.number + 1;
        const total = self.sync_target.?.number - head.number;
        var persisted: u64 = 0;
        while (persisted < total) {
            const count = @min(header_persist_chunk, total - persisted);
            const headers = try self.readDownladedHeaders(self.allocator, first + persisted, count);
            defer self.allocator.free(headers);
            try self.bc.appendHeaders(headers);
            persisted += count;
        }

        try self.clearDownloadedHeaders();
        self.sync_target = null;
    }

    fn updatePivot(self: *Self) !void {
        if (self.sync_target == null or self.state != .initial) return;

        const sync_target_height = self.sync_target.?.number;
        const new_pivot_height = if (sync_target_height > 32) sync_target_height - 32 else 0;
        const new_pivot = try self.readDownladedHeader(new_pivot_height) orelse
            (try self.bc.readHeader(new_pivot_height) orelse return);

        const cur_pivot = self.state.initial.pivot;
        if (cur_pivot == null or new_pivot_height - cur_pivot.?.number >= 64) {
            self.state.initial.previous_pivot = cur_pivot;
            self.state.initial.pivot = new_pivot;
            log.debug("new pivot {}, old {any}", .{ new_pivot, cur_pivot });
            if (cur_pivot == null)
                self.requestAccountRange(
                    self.free_snap_requests.pop() orelse unreachable,
                    new_pivot.state_root,
                    @splat(0),
                    @splat(0xff),
                );
        }
    }

    fn sendSnapMessage(self: *Self, msg: snap.Message) !rlpx.Server.PeerId {
        const peer = try self.snap_provider.pickRandomPeer(HeightFilter.init(self.state.initial.pivot.?.number, self));
        try self.snap_provider.send(peer, msg);
        return peer;
    }

    fn requestAccountRange(self: *Self, req: *Request(snap.Message), state_root: [32]u8, origin: [32]u8, limit: [32]u8) void {
        log.debug("requesting account range origin: {x} limit: {x}", .{ origin, limit });
        const id = self.snap_provider.nextRequestId();
        const msg: snap.Message = .{ .get_account_range = .{
            .id = id,
            .root = state_root,
            .origin = origin,
            .limit = limit,
        } };

        req.* = .{
            .id = id,
            .peer = self.sendSnapMessage(msg) catch invalid_peer,
            .msg = msg,
            .deadline = std.Io.Clock.now(.real, self.io).addDuration(.fromSeconds(3)),
        };
        self.inflight_snap_requests.push(req);
    }

    fn handleSnap(self: *Self, msg: snap.Message, peer: rlpx.Server.PeerId) !void {
        switch (msg) {
            .account_range => |account_range| {
                if (matchRequest(snap.Message, &self.inflight_snap_requests, peer, account_range.id, .get_account_range)) |request| {
                    try self.handleAccounts(request, &account_range);
                }
            },
            else => {},
        }
    }

    fn handleAccounts(self: *Self, request: *Request(snap.Message), response: *const snap.AccountRange) !void {
        const allocator = self.snap_arena.allocator();

        const get_accounts_range = request.msg.get_account_range;
        var hashes: [][32]u8 = try allocator.alloc([32]u8, response.accounts.len);
        var accounts: [][]const u8 = try allocator.alloc([]const u8, response.accounts.len);
        for (response.accounts, 0..) |elem, index| {
            hashes[index] = elem.hash;

            var slim_account: snap.SlimAccount = undefined;
            _ = try rlp.deserialize(snap.SlimAccount, allocator, elem.account.value, &slim_account);

            var list = std.array_list.Managed(u8).init(allocator);
            try rlp.serialize(types.Account, allocator, slimToFullAccount(slim_account), &list);
            accounts[index] = try list.toOwnedSlice();
        }

        var proof: trie.NodesHashMap = .empty;
        if (response.proof.len > 0) {
            try proof.ensureTotalCapacity(allocator, @intCast(response.proof.len));

            for (response.proof) |node| {
                var h: [32]u8 align(8) = undefined;
                std.crypto.hash.sha3.Keccak256.hash(node, &h, .{});
                try proof.put(allocator, h, node);
            }
        }

        var remaining: ?struct { [32]u8, [32]u8 } = null;
        if (verifyRangeProof(
            allocator,
            get_accounts_range.root,
            get_accounts_range.origin,
            hashes,
            accounts,
            if (response.proof.len > 0) &proof else null,
        )) |has_more| {
            const last = if (hashes.len > 0) hashes[hashes.len - 1] else get_accounts_range.limit;
            log.debug("verified account range {x}-{x}", .{ get_accounts_range.origin, last });
            if (has_more and std.mem.order(u8, &last, &get_accounts_range.limit) == .lt)
                remaining = .{ last, get_accounts_range.limit };
            try self.persistAccounts(hashes, response);
        } else |_| {
            remaining = .{ get_accounts_range.origin, get_accounts_range.limit };
        }

        if (remaining) |range| {
            const origin = range.@"0";
            const limit = range.@"1";
            log.debug("remaining account range {x}-{x}", .{ origin, limit });

            const origin_numeric = std.mem.readInt(u256, &origin, .big);
            const limit_numeric = std.mem.readInt(u256, &limit, .big);
            const min_range = (std.math.maxInt(u256) / (1 << 16));

            const new_state_root = self.state.initial.pivot.?.state_root;

            if (limit_numeric - origin_numeric < min_range) {
                self.requestAccountRange(request, new_state_root, origin, limit);
            } else if (self.free_snap_requests.pop()) |new_req| {
                var split_point: [32]u8 = undefined;
                std.mem.writeInt(u256, &split_point, origin_numeric / 2 + limit_numeric / 2, .big);
                self.requestAccountRange(new_req, new_state_root, origin, split_point);
                self.requestAccountRange(request, new_state_root, split_point, limit);
            } else {
                self.requestAccountRange(request, new_state_root, origin, limit);
            }
        } else {
            self.free_snap_requests.push(request);
        }
    }

    fn persistAccounts(self: *Self, hashes: [][32]u8, response: *const snap.AccountRange) !void {
        const txn = try self.eth_db.kv_store.transaction_rw();
        errdefer _ = txn.abort() catch |e| {
            log.err("failed to abort txn {}", .{e});
        };

        const table = self.eth_db.kv_store.table(txn, .accounts);
        for (hashes, 0..) |hash, index| {
            try table.set(&hash, response.accounts[index].account.value, .Upsert);
        }

        try txn.commit();
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

const invalid_peer: rlpx.Server.PeerId = .{
    .peer_index = std.math.maxInt(usize),
    .peer_epoch = std.math.maxInt(usize),
};

const HeightFilter = struct {
    min_height: u64,
    downloader: *Downloader,

    fn init(min_height: u64, downloader: *Downloader) HeightFilter {
        return .{ .downloader = downloader, .min_height = min_height };
    }

    pub fn validPeer(self: *const HeightFilter, peer_id: rlpx.Server.PeerId) bool {
        if (self.downloader.peer_ranges[peer_id.peer_index]) |peer_range| {
            return peer_range.id.peer_epoch == peer_id.peer_epoch and self.min_height <= peer_range.range.latest_block;
        }
        return false;
    }
};

fn slimToFullAccount(slim: snap.SlimAccount) types.Account {
    return .{
        .balance = slim.balance,
        .nonce = slim.nonce,
        .code_hash = if (slim.code_hash.len == 32)
            slim.code_hash[0..32].*
        else
            types.empty_code_hash,
        .storage_hash = if (slim.root.len == 32)
            slim.root[0..32].*
        else
            types.empty_root_hash,
    };
}
