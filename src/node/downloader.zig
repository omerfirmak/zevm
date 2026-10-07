const std = @import("std");
const Blockchain = @import("blockchain.zig").Blockchain;
const rlpx = @import("../devp2p/rlpx.zig");
const eth = @import("../devp2p/eth.zig");
const snap = @import("../devp2p/snap.zig");
const types = @import("../types.zig");
const rlp = @import("rlp");
const trie = @import("../trie/trie.zig");
const kv = @import("../db/kv.zig");
const lmdbx = @import("lmdbx");

const verifyRangeProof = @import("../trie/range_proof.zig").verifyRangeProof;
const EthDb = @import("../db/eth.zig").Eth;
const List = @import("../free_list.zig").List;
const max_inflight_requests = 100;
const max_inflight_requests_per_peer = 2;
const header_persist_chunk = 1024;
const batch_storage_code_req_size = 256;
const progress_log_interval: std.Io.Duration = .fromSeconds(8);
const arena_retain_limit = (32 << 20) - 64;

const log = std.log.scoped(.downloader);

fn Request(comptime msg: type) type {
    return struct {
        id: u64,
        peer: rlpx.Server.PeerId,
        msg: msg,
        sent_at: std.Io.Timestamp,
        deadline: std.Io.Timestamp,
        keyspace: [2]u256 = .{ 0, 0 },
    };
}

pub const Downloader = struct {
    const Self = @This();
    pub const SyncTarget = struct {
        paused: bool = false,

        number: u64,
        hash: [32]u8,

        cutoff_number: u64, // last header to fetch, inclusive
        cutoff_hash: [32]u8,
    };
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
    inflight_eth_requests: List(Request(eth.Message)) = .{},
    pending_eth_requests: List(Request(eth.Message)) = .{},

    snap_arena: std.heap.ArenaAllocator,
    snap_provider: *snap.Provider,
    free_snap_requests: List(Request(snap.Message)),
    inflight_snap_requests: List(Request(snap.Message)) = .{},
    pending_snap_requests: List(Request(snap.Message)) = .{},
    stashed_snap_requests: []Request(snap.Message),

    sync_target: SyncTarget,
    sync_target_mutex: std.Io.Mutex = .init,
    header: ?struct {
        requested_header_head: u64,
        requested_header_tail: u64,
    } = null,
    state: ?struct {
        pivot: types.BlockHeader,

        accounts_done: bool = false,
        storage_fetch_head: [32]u8 = @splat(0),
        storage_and_fetch_initiated: bool = false,
    } = null,
    state_heal: ?struct {
        next_pivot: types.BlockHeader,
        target_pivot: types.BlockHeader,
        start_number: u64,
        started_at: std.Io.Timestamp,

        bal_requested: bool = false,
        bal: ?struct {
            arena: std.heap.ArenaAllocator,
            rlp: rlp.RawValue,
            parsed: types.BlockAccessLists,
            resume_index: usize = 0,
        } = null,
        pivot_hash_buf: [1][32]u8 = undefined,
    } = null,
    progress: struct {
        headers: u64 = 0,
        account_keyspace: u256 = 0,
        storage_keyspace: u256 = 0,
        code_keyspace: u256 = 0,
        last_log: ?std.Io.Timestamp = null,
    } = .{},

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

        var stashed_snap_requests = try allocator.alloc(Request(snap.Message), max_inflight_requests);
        stashed_snap_requests.len = 0;

        const head = try bc.head();

        return .{
            .io = io,
            .allocator = allocator,
            .bc = bc,
            .eth_db = eth_db,
            .eth_arena = .init(allocator),
            .eth_provider = eth_provider,
            .free_eth_requests = try .init(allocator, max_inflight_requests),
            .snap_arena = .init(allocator),
            .snap_provider = snap_provider,
            .free_snap_requests = try .init(allocator, max_inflight_requests),
            .stashed_snap_requests = stashed_snap_requests,
            .peer_ranges = peer_ranges,
            .sync_target = .{
                .number = head.number,
                .hash = head.hash,
                .cutoff_number = head.number,
                .cutoff_hash = head.hash,
            },
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

        try select.concurrent(.eth, eth.Provider.next, .{ self.eth_provider, self.io, self.eth_arena.allocator(), self.allocator });
        try select.concurrent(.snap, snap.Provider.next, .{ self.snap_provider, self.io, self.snap_arena.allocator(), self.allocator });
        try select.concurrent(.tick, std.Io.sleep, .{ self.io, .fromSeconds(1), .real });

        while (true) {
            switch (select.await() catch |e| return e) {
                .eth => |res| {
                    defer {
                        _ = self.eth_arena.reset(.{ .retain_with_limit = arena_retain_limit });
                        select.concurrent(.eth, eth.Provider.next, .{ self.eth_provider, self.io, self.eth_arena.allocator(), self.allocator }) catch |e| std.debug.panic("downloader: failed to spawn task: {}", .{e});
                    }
                    const received_message = res catch continue;
                    defer self.allocator.free(received_message.read.payload);
                    try self.handleEth(received_message.msg, received_message.read.peer);
                },
                .snap => |res| {
                    defer {
                        _ = self.snap_arena.reset(.{ .retain_with_limit = arena_retain_limit });
                        select.concurrent(.snap, snap.Provider.next, .{ self.snap_provider, self.io, self.snap_arena.allocator(), self.allocator }) catch |e| std.debug.panic("downloader: failed to spawn task: {}", .{e});
                    }
                    const received_message = res catch continue;
                    defer self.allocator.free(received_message.read.payload);
                    try self.handleSnap(received_message.msg, received_message.read.peer);
                },
                .tick => {
                    defer select.concurrent(.tick, std.Io.sleep, .{ self.io, .fromSeconds(1), .real }) catch |e| std.debug.panic("downloader: failed to spawn task: {}", .{e});
                    try self.handleTick();
                },
            }
        }
    }

    fn handleTick(self: *Self) !void {
        self.logProgress();
        if (self.header != null) {
            try self.advanceHeaderDownload();
        }
        if (self.state != null) {
            try self.updatePivot();
            try self.advanceStateDownload();
        }
        if (self.state_heal != null) {
            try self.advanceStateHeal();
        }
        try self.checkEthRequestTimeouts();
        try self.checkSnapRequestTimeouts();
    }

    fn checkEthRequestTimeouts(self: *Self) !void {
        self.checkRequestTimeouts(eth.Message, &self.inflight_eth_requests, &self.pending_eth_requests, self.eth_provider);
        self.drainPendingEthRequests();
    }

    fn checkSnapRequestTimeouts(self: *Self) !void {
        self.checkRequestTimeouts(snap.Message, &self.inflight_snap_requests, &self.pending_snap_requests, self.snap_provider);
        self.drainPendingSnapRequests();
    }

    fn checkRequestTimeouts(
        self: *Self,
        comptime Message: type,
        list: *List(Request(Message)),
        pending: *List(Request(Message)),
        provider: anytype,
    ) void {
        var current_node = list.inner.first;

        const now = std.Io.Clock.now(.real, self.io);
        while (current_node) |node| {
            const next_node = node.next;
            const request: *List(Request(Message)).Node = @alignCast(@fieldParentPtr("node", node));

            if (request.elem.deadline.toMilliseconds() < now.toMilliseconds()) {
                if (!std.meta.eql(request.elem.peer, invalid_peer)) {
                    log.warn("{t} request {} to {} timed out after {}ms (timeout {}ms)", .{
                        std.meta.activeTag(request.elem.msg),
                        request.elem.id,
                        request.elem.peer,
                        request.elem.sent_at.durationTo(now).toMilliseconds(),
                        request.elem.sent_at.durationTo(request.elem.deadline).toMilliseconds(),
                    });
                }
                const assumed_rtt: std.Io.Duration = .fromNanoseconds(request.elem.sent_at.durationTo(now).nanoseconds * 2);
                provider.observeDelay(request.elem.peer, std.meta.activeTag(request.elem.msg), assumed_rtt);
                list.inner.remove(node);
                pending.prepend(&request.elem);
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
                if (self.matchRequest(eth.Message, self.eth_provider, &self.inflight_eth_requests, peer, headers.request_id, .get_block_headers)) |req|
                    try self.handleHeaders(req, headers);
            },
            .block_access_list => |access_lists| {
                if (self.matchRequest(eth.Message, self.eth_provider, &self.inflight_eth_requests, peer, access_lists.request_id, .get_block_access_list)) |req| {
                    try self.handleBals(req, access_lists);
                }
            },
            else => {},
        }
        self.drainPendingEthRequests();
    }

    pub fn syncTarget(self: *Self) SyncTarget {
        self.sync_target_mutex.lockUncancelable(self.io);
        defer self.sync_target_mutex.unlock(self.io);
        return self.sync_target;
    }

    fn updateTarget(self: *Self, number: u64, hash: [32]u8) !void {
        const head = try self.bc.head();
        if (head.number >= number) return;

        {
            self.sync_target_mutex.lockUncancelable(self.io);
            defer self.sync_target_mutex.unlock(self.io);

            if (self.sync_target.paused) return;
            if (self.sync_target.number >= number) return;
            if (self.sync_target.number <= head.number) self.progress.headers = 0;

            self.sync_target = .{
                .hash = hash,
                .number = number,
                .cutoff_number = head.number,
                .cutoff_hash = head.hash,
            };
        }

        if (head.number == 0 and self.header == null) {
            self.header = .{
                .requested_header_head = 0,
                .requested_header_tail = std.math.maxInt(u64),
            };
            self.state = .{ .pivot = try self.bc.readHeader(0) orelse unreachable };
        }

        try self.updatePivot();
    }

    fn pickEthPeer(self: *Self, msg: eth.Message) !rlpx.Server.PeerId {
        switch (msg) {
            .get_block_headers => |header_req| {
                const height = switch (header_req.range.origin) {
                    .number => |number| number,
                    .hash => self.syncTarget().number,
                };
                return self.eth_provider.pickRandomPeer(PeerFilter(eth.Message).init(self, &self.inflight_eth_requests, height));
            },
            else => {},
        }
        return self.eth_provider.pickRandomPeer(PeerFilter(eth.Message).init(self, &self.inflight_eth_requests, null));
    }

    fn sendRequest(self: *Self, provider: anytype, pick_peer_fn: anytype, req: anytype) !void {
        const sent_at = std.Io.Clock.now(.real, self.io);
        errdefer {
            req.peer = invalid_peer;
            req.deadline = sent_at;
        }

        req.id = provider.nextRequestId();
        switch (req.msg) {
            inline else => |*msg| if (@hasField(@TypeOf(msg.*), "id")) {
                msg.id = req.id;
            },
        }
        req.sent_at = sent_at;
        req.peer = try pick_peer_fn(self, req.msg);
        try provider.send(req.peer, req.msg);
        req.deadline = sent_at.addDuration(try provider.timeoutFor(req.peer, std.meta.activeTag(req.msg)));
    }

    fn reissueEthRequest(self: *Self, req: *Request(eth.Message)) !void {
        return self.sendRequest(self.eth_provider, Self.pickEthPeer, req);
    }

    fn sendEthRequest(self: *Self, req: *Request(eth.Message), urgent: bool) void {
        if (urgent) self.pending_eth_requests.prepend(req) else self.pending_eth_requests.push(req);
        self.drainPendingEthRequests();
    }

    fn drainPendingEthRequests(self: *Self) void {
        drainPendingRequests(self, &self.pending_eth_requests, &self.inflight_eth_requests, Self.reissueEthRequest);
    }

    fn drainPendingRequests(self: *Self, pending: anytype, inflight: anytype, send_fn: anytype) void {
        while (pending.pop()) |req| {
            send_fn(self, req) catch return pending.prepend(req);
            inflight.push(req);
        }
    }

    fn advanceHeaderDownload(self: *Self) !void {
        const target = self.syncTarget();

        var status = &self.header.?;
        if (status.requested_header_tail != std.math.maxInt(u64) and status.requested_header_head < target.number) {
            // target moved, fill the gap from new head to old head
            requestHeaders(
                self,
                self.free_eth_requests.pop() orelse return,
                .{ .hash = target.hash },
                target.number - status.requested_header_head,
            );
            status.requested_header_head = target.number;
        }

        while (status.requested_header_tail > target.cutoff_number) {
            const origin: eth.HashOrNumber, const origin_num = if (status.requested_header_tail == std.math.maxInt(u64))
                .{ .{ .hash = target.hash }, target.number }
            else
                .{ .{ .number = status.requested_header_tail }, status.requested_header_tail };
            const batch_size = @as(u64, @min(1023, origin_num - target.cutoff_number)) + 1;
            requestHeaders(
                self,
                self.free_eth_requests.pop() orelse return,
                origin,
                batch_size,
            );
            status.requested_header_tail = (origin_num + 1) - batch_size;
            if (status.requested_header_head < origin_num)
                status.requested_header_head = origin_num;
        }
    }

    fn requestHeaders(self: *Self, req: *Request(eth.Message), origin: eth.HashOrNumber, amount: u64) void {
        req.msg = .{ .get_block_headers = .{ .range = .{
            .origin = origin,
            .amount = amount,
            .skip = 0,
            .reverse = true,
        } } };
        self.sendEthRequest(req, origin == .hash);
        log.debug("requesting headers origin {} amount {}", .{ origin, amount });
    }

    fn handleHeaders(self: *Self, matched_request: *Request(eth.Message), response: eth.BlockHeaders) !void {
        const headers_request = matched_request.msg.get_block_headers;

        const hashes, const headers = self.validateHeadersResponse(headers_request, response) catch |e| {
            log.debug("header validation failed for origin {} amount {}: {t}", .{ headers_request.range.origin, headers_request.range.amount, e });
            self.requestHeaders(matched_request, headers_request.range.origin, headers_request.range.amount);
            return;
        };

        var followup_request: ?@TypeOf(headers_request.range) = null;
        if (headers.len > 0) {
            const invalidated_range = try self.persistDownloadedHeaderChain(
                headers,
                hashes,
                headers_request.range.amount,
            );
            if (invalidated_range) |range| {
                followup_request = .{
                    .origin = .{ .hash = range.origin },
                    .amount = range.amount,
                };
            } else if (headers_request.range.amount > headers.len and headers[0].number > 0) {
                followup_request = .{
                    .origin = .{ .hash = headers[0].parent_hash },
                    .amount = headers_request.range.amount - headers.len,
                };
            }
            self.progress.headers += headers.len;
            log.debug("validated header range start {} end {} invalidated {any}", .{ headers[0].number, headers[0].number + headers.len - 1, invalidated_range });
        } else followup_request = headers_request.range;

        if (followup_request) |followup| {
            self.requestHeaders(matched_request, followup.origin, followup.amount);
        } else {
            self.free_eth_requests.push(matched_request);
            try self.advanceHeaderDownload();
        }

        try self.checkHeaderDownloadComplete();
    }

    fn validateHeadersResponse(
        self: *Self,
        request: eth.GetBlockHeaders,
        response: eth.BlockHeaders,
    ) !struct { [][32]u8, []types.BlockHeader } {
        if (response.rlps.len == 0) return .{ &[_][32]u8{}, &[_]types.BlockHeader{} };

        const allocator = self.eth_arena.allocator();
        var headers: []types.BlockHeader = try allocator.alloc(types.BlockHeader, response.rlps.len);
        var hashes: [][32]u8 = try allocator.alloc([32]u8, response.rlps.len);
        for (response.rlps, 0..) |header_rlp, index| {
            const canon_index = if (request.range.reverse) response.rlps.len - index - 1 else index;
            _ = try rlp.deserialize(types.BlockHeader, allocator, header_rlp.value, &headers[canon_index]);
            std.crypto.hash.sha3.Keccak256.hash(header_rlp.value, &hashes[canon_index], .{});
        }

        for (1..headers.len) |i| {
            if (!std.meta.eql(hashes[i - 1], headers[i].parent_hash)) {
                return error.InvalidHeaderChain;
            }
        }

        switch (request.range.origin) {
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
        const target = self.syncTarget();
        if (self.header.?.requested_header_head < target.number or
            self.header.?.requested_header_tail > target.cutoff_number)
            return;

        if (!self.pending_eth_requests.empty()) return;
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
            target.number,
        });

        const first = head.number + 1;
        const total = target.number - head.number;
        var persisted: u64 = 0;
        while (persisted < total) {
            const count = @min(header_persist_chunk, total - persisted);
            const headers = try self.readDownladedHeaders(self.allocator, first + persisted, count);
            defer self.allocator.free(headers);
            try self.bc.appendHeaders(headers);
            persisted += count;
        }

        try self.clearDownloadedHeaders();
    }

    fn updatePivot(self: *Self) !void {
        if (self.state == null) return;

        const head_height = self.syncTarget().number;
        const new_pivot_height = if (head_height > 32) head_height - 32 else 0;

        const cur_pivot = self.state.?.pivot;
        if (new_pivot_height - cur_pivot.number >= 64) {
            const new_pivot = try self.readHeader(new_pivot_height) orelse return;

            if (cur_pivot.number != 0) {
                const no_reorg = self.headerIsInTargetChain(cur_pivot) catch |e| {
                    if (e == error.Maybe) return;
                    return e;
                };
                std.debug.assert(no_reorg);

                if (self.state_heal) |*state_heal| {
                    state_heal.target_pivot = try self.readHeader(new_pivot_height) orelse unreachable;
                    log.info("state heal: target moved to {}", .{new_pivot_height});
                } else {
                    self.stashSnapRequests();
                    self.state_heal = .{
                        .target_pivot = try self.readHeader(new_pivot_height) orelse unreachable,
                        .next_pivot = try self.readHeader(cur_pivot.number + 1) orelse unreachable,
                        .start_number = cur_pivot.number,
                        .started_at = std.Io.Clock.now(.real, self.io),
                    };
                    log.info("state heal: started, pivot {} -> {} ({} blocks, {} snap requests stashed)", .{
                        cur_pivot.number,
                        new_pivot_height,
                        new_pivot_height - cur_pivot.number,
                        self.stashed_snap_requests.len,
                    });
                }
            } else {
                self.requestAccountRange(
                    self.free_snap_requests.pop() orelse unreachable,
                    new_pivot.state_root,
                    @splat(0),
                    @splat(0xff),
                );
            }

            log.debug("new pivot {}, old {}", .{ new_pivot, cur_pivot });
            self.state.?.pivot = new_pivot;
        }
    }

    fn advanceStateDownload(self: *Self) !void {
        if (self.state_heal != null) return; // state download is paused

        const state = &self.state.?;

        if (state.accounts_done and !state.storage_and_fetch_initiated)
            try self.advanceStorageAndCodeDownload();

        if (self.state.?.pivot.number > 0 and self.inflight_snap_requests.empty() and
            self.pending_snap_requests.empty() and self.stashed_snap_requests.len == 0)
        {
            if (state.accounts_done and state.storage_and_fetch_initiated) {
                self.state = null;
                log.info("state download done", .{});
            } else {
                state.accounts_done = true;
                log.info("account download done", .{});
            }
        }
    }

    fn advanceStorageAndCodeDownload(self: *Self) !void {
        const state = &self.state.?;

        if (self.free_snap_requests.empty()) return;

        const txn = try self.eth_db.kv_store.transaction_ro();
        defer txn.abort() catch unreachable;
        const accounts_table = self.eth_db.kv_store.table(txn, .accounts);
        const account_iterator = try accounts_table.cursor();
        defer account_iterator.deinit();
        const codes_table = self.eth_db.kv_store.table(txn, .codes);
        const codes_iterator = try codes_table.cursor();
        defer codes_iterator.deinit();

        if (try account_iterator.seekLowerBound(&state.storage_fetch_head) == null) {
            state.storage_and_fetch_initiated = true;
            return;
        }

        while (true) {
            const code_request = self.free_snap_requests.pop();
            const storage_request = self.free_snap_requests.pop();
            if (storage_request == null) {
                if (code_request) |req|
                    self.free_snap_requests.push(req);
                return;
            }
            errdefer {
                self.free_snap_requests.push(code_request.?);
                self.free_snap_requests.push(storage_request.?);
            }

            var account_hashes = try self.allocator.alloc([32]u8, batch_storage_code_req_size);
            account_hashes.len = 0;
            errdefer {
                account_hashes.len = batch_storage_code_req_size;
                self.allocator.free(account_hashes);
            }
            var code_hashes = try self.allocator.alloc([32]u8, batch_storage_code_req_size);
            code_hashes.len = 0;
            errdefer {
                code_hashes.len = batch_storage_code_req_size;
                self.allocator.free(code_hashes);
            }

            const batch_start = std.mem.readInt(u256, &state.storage_fetch_head, .big);
            const accounts_exhausted = while (true) {
                const cur = try account_iterator.getCurrentEntry();
                state.storage_fetch_head = cur.key[0..32].*;

                const acc = EthDb.decodeAccount(self.allocator, cur.value) catch unreachable;

                var has_code = false;
                if (!std.meta.eql(acc.code_hash, types.empty_code_hash)) {
                    has_code = if (try codes_iterator.seekLowerBound(&acc.code_hash)) |res| !res.exact else true;
                }
                const has_storage = !std.meta.eql(acc.storage_hash, types.empty_root_hash);

                if (has_code and code_hashes.len == batch_storage_code_req_size or
                    has_storage and account_hashes.len == batch_storage_code_req_size)
                    break false;

                if (has_code) {
                    code_hashes.len += 1;
                    code_hashes[code_hashes.len - 1] = acc.code_hash;
                }

                if (has_storage) {
                    account_hashes.len += 1;
                    account_hashes[account_hashes.len - 1] = cur.key[0..32].*;
                }

                if (try account_iterator.goToNext() == null) break true;
            };

            const batch_end = if (accounts_exhausted) std.math.maxInt(u256) else std.mem.readInt(
                u256,
                &state.storage_fetch_head,
                .big,
            );
            storage_request.?.keyspace = .{ batch_start, batch_end };
            code_request.?.keyspace = .{ batch_start, batch_end };
            self.requestStorageRanges(storage_request.?, state.pivot.state_root, account_hashes);
            self.requestCodes(code_request.?, code_hashes);

            if (accounts_exhausted) {
                state.storage_and_fetch_initiated = true;
                return;
            }
        }
    }

    fn requestStorageRanges(self: *Self, req: *Request(snap.Message), state_root: [32]u8, accounts: [][32]u8) void {
        log.debug("requesting storage ranges accounts: {}", .{accounts.len});
        req.msg = .{ .get_storage_ranges = .{
            .account_hashes = accounts,
            .root_hash = state_root,
        } };
        self.sendSnapRequest(req) catch {};
    }

    fn requestCodes(self: *Self, req: *Request(snap.Message), code_hashes: [][32]u8) void {
        log.debug("requesting codes: {}", .{code_hashes.len});
        req.msg = .{ .get_byte_codes = .{
            .hashes = code_hashes,
        } };
        self.sendSnapRequest(req) catch {};
    }

    fn stashSnapRequests(self: *Self) void {
        while (self.inflight_snap_requests.pop() orelse self.pending_snap_requests.pop()) |node| {
            self.stashed_snap_requests.len += 1;
            self.stashed_snap_requests[self.stashed_snap_requests.len - 1] = node.*;
            self.free_snap_requests.push(node);
        }
    }

    fn popSnapRequests(self: *Self) void {
        std.debug.assert(self.inflight_snap_requests.empty() and self.pending_snap_requests.empty());

        const pivot_root = self.state.?.pivot.state_root;

        for (self.stashed_snap_requests) |stashed_req| {
            const req = self.free_snap_requests.pop() orelse unreachable;
            req.* = stashed_req;
            switch (req.msg) {
                .get_account_range => |*account_range_req| account_range_req.root = pivot_root,
                .get_storage_ranges => |*storage_ranges_req| storage_ranges_req.root_hash = pivot_root,
                else => {},
            }

            self.sendSnapRequest(req) catch {};
        }
        self.stashed_snap_requests.len = 0;
    }

    fn requestBals(self: *Self, req: *Request(eth.Message), hashes: [][32]u8) void {
        req.msg = .{ .get_block_access_list = .{ .hashes = hashes } };
        self.sendEthRequest(req, true);
    }

    fn advanceStateHeal(self: *Self) !void {
        const state_heal = &self.state_heal.?;

        if (state_heal.bal) |*bal| {
            if (bal.resume_index < bal.parsed.len) {
                bal.resume_index = try self.applyBal(bal.parsed, bal.resume_index);
            }
            if (bal.resume_index == bal.parsed.len and self.inflight_snap_requests.empty() and self.pending_snap_requests.empty()) {
                if (state_heal.next_pivot.number + 1 > state_heal.target_pivot.number) {
                    log.info("state heal: done, healed {} blocks in {}s", .{
                        state_heal.target_pivot.number - state_heal.start_number,
                        state_heal.started_at.durationTo(std.Io.Clock.now(.real, self.io)).toSeconds(),
                    });
                    bal.arena.deinit();
                    self.state_heal = null;
                    self.popSnapRequests();
                    return;
                }

                state_heal.next_pivot = try self.readHeader(state_heal.next_pivot.number + 1) orelse unreachable;
                std.debug.assert(std.meta.eql(state_heal.pivot_hash_buf[0], state_heal.next_pivot.parent_hash));
                state_heal.pivot_hash_buf[0] = state_heal.next_pivot.hash();
                state_heal.bal_requested = false;

                bal.arena.deinit();
                state_heal.bal = null;
            }
        }

        if (state_heal.bal_requested == false) {
            const bal_req = self.free_eth_requests.pop() orelse return;

            state_heal.pivot_hash_buf[0] = state_heal.next_pivot.hash();
            self.requestBals(bal_req, state_heal.pivot_hash_buf[0..1]);
            state_heal.bal_requested = true;
        }
    }

    fn pickSnapPeer(self: *Self, _: snap.Message) !rlpx.Server.PeerId {
        return self.snap_provider.pickRandomPeer(PeerFilter(snap.Message).init(self, &self.inflight_snap_requests, self.state.?.pivot.number));
    }

    fn reissueSnapRequest(self: *Self, req: *Request(snap.Message)) !void {
        return self.sendRequest(self.snap_provider, Self.pickSnapPeer, req);
    }

    fn sendSnapRequest(self: *Self, req: *Request(snap.Message)) !void {
        self.pending_snap_requests.push(req);
        self.drainPendingSnapRequests();
    }

    fn drainPendingSnapRequests(self: *Self) void {
        drainPendingRequests(self, &self.pending_snap_requests, &self.inflight_snap_requests, Self.reissueSnapRequest);
    }

    fn requestAccountRange(self: *Self, req: *Request(snap.Message), state_root: [32]u8, origin: [32]u8, limit: [32]u8) void {
        log.debug("requesting account range origin: {x} limit: {x}", .{ origin, limit });
        req.msg = .{ .get_account_range = .{
            .root = state_root,
            .origin = origin,
            .limit = limit,
        } };
        self.sendSnapRequest(req) catch {};
    }

    fn handleSnap(self: *Self, msg: snap.Message, peer: rlpx.Server.PeerId) !void {
        switch (msg) {
            .account_range => |account_range| {
                if (self.matchRequest(snap.Message, self.snap_provider, &self.inflight_snap_requests, peer, account_range.id, .get_account_range)) |request| {
                    try self.handleAccounts(request, &account_range);
                }
            },
            .storage_ranges => |storage_ranges| {
                if (self.matchRequest(snap.Message, self.snap_provider, &self.inflight_snap_requests, peer, storage_ranges.id, .get_storage_ranges)) |req| {
                    try self.handleStorage(req, &storage_ranges);
                }
            },
            .byte_codes => |byte_codes| {
                if (self.matchRequest(snap.Message, self.snap_provider, &self.inflight_snap_requests, peer, byte_codes.id, .get_byte_codes)) |req| {
                    try self.handleCodes(req, byte_codes);
                }
            },
            else => {},
        }
        self.drainPendingSnapRequests();
        if (self.state != null)
            try self.advanceStateDownload();
        if (self.state_heal != null)
            try self.advanceStateHeal();
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
            try self.persistAccounts(get_accounts_range, hashes, response);
            const covered_until = if (has_more) last else get_accounts_range.limit;
            self.progress.account_keyspace +|= std.mem.readInt(u256, &covered_until, .big) - std.mem.readInt(u256, &get_accounts_range.origin, .big);
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

            const pivot_state_root = self.state.?.pivot.state_root;
            if (limit_numeric - origin_numeric < min_range) {
                self.requestAccountRange(request, pivot_state_root, origin, limit);
            } else if (self.free_snap_requests.pop()) |new_req| {
                var split_point: [32]u8 = undefined;
                std.mem.writeInt(u256, &split_point, origin_numeric / 2 + limit_numeric / 2, .big);
                self.requestAccountRange(new_req, pivot_state_root, origin, split_point);
                self.requestAccountRange(request, pivot_state_root, split_point, limit);
            } else {
                self.requestAccountRange(request, pivot_state_root, origin, limit);
            }
        } else {
            self.free_snap_requests.push(request);
        }
    }

    fn persistAccounts(self: *Self, request: snap.GetAccountRange, hashes: [][32]u8, response: *const snap.AccountRange) !void {
        const txn = try self.eth_db.kv_store.transaction_rw();
        errdefer _ = txn.abort() catch |e| {
            log.err("failed to abort txn {}", .{e});
        };

        const table = self.eth_db.kv_store.table(txn, .accounts);
        for (hashes, 0..) |hash, index| {
            try table.set(&hash, response.accounts[index].account.value, .Upsert);
        }
        // a proven single account query that doesn't return the account means it no longer exists
        if (std.meta.eql(request.origin, request.limit) and (hashes.len == 0 or !std.meta.eql(hashes[0], request.origin))) {
            try self.eth_db.deleteAccount(txn, request.origin);
        }

        try txn.commit();
    }

    fn handleBals(self: *Self, req: *Request(eth.Message), access_lists: eth.BlockAccessLists) !void {
        if (self.state_heal) |*state_heal| {
            if (access_lists.rlps.len >= 1) {
                var calculated_hash: [32]u8 = undefined;
                std.crypto.hash.sha3.Keccak256.hash(access_lists.rlps[0].value, &calculated_hash, .{});
                if (std.meta.eql(calculated_hash, state_heal.next_pivot.block_access_list_hash.?)) {
                    var bal: types.BlockAccessLists = undefined;
                    if (rlp.deserialize(types.BlockAccessLists, self.eth_arena.allocator(), access_lists.rlps[0].value, &bal)) |_| {
                        std.debug.assert(state_heal.bal == null);

                        // the raw rlp points into the message payload, which is freed after this handler
                        const bal_rlp = try self.eth_arena.allocator().dupe(u8, access_lists.rlps[0].value);
                        // the parsed bal outlives this message, take ownership of the eth arena it lives in
                        const arena = self.eth_arena;
                        self.eth_arena = .init(self.allocator);
                        state_heal.bal = .{
                            .arena = arena,
                            .rlp = .{ .value = bal_rlp },
                            .parsed = bal,
                        };
                        self.free_eth_requests.push(req);
                        try self.advanceStateHeal();
                        return;
                    } else |_| {}
                }
            }
            self.requestBals(req, state_heal.pivot_hash_buf[0..1]);
        } else unreachable;
    }

    fn applyBal(self: *Self, bal: types.BlockAccessLists, resume_index: usize) !usize {
        const txn = try self.eth_db.kv_store.transaction_rw();
        defer txn.commit() catch unreachable;
        const codes = self.eth_db.kv_store.table(txn, .codes);

        for (resume_index..bal.len) |account_index| {
            const changes = bal[account_index];
            if (changes.balance_changes.len == 0 and
                changes.code_changes.len == 0 and
                changes.nonce_changes.len == 0 and
                changes.storage_changes.len == 0) continue;

            var addr_buf: [20]u8 = undefined;
            std.mem.writeInt(u160, &addr_buf, changes.addr, .big);
            var addr_hash: [32]u8 = undefined;
            std.crypto.hash.sha3.Keccak256.hash(&addr_buf, &addr_hash, .{});
            var code_hash: [32]u8 = types.empty_code_hash;
            if (changes.code_changes.len > 0) {
                const code = changes.code_changes[changes.code_changes.len - 1].code;
                std.crypto.hash.sha3.Keccak256.hash(code, &code_hash, .{});
                codes.set(&code_hash, code, .Create) catch |e| {
                    if (e != lmdbx.Error.MDBX_KEYEXIST) return e;
                };
            }

            for (changes.storage_changes) |slot_changes| {
                if (slot_changes.changes.len == 0) continue;
                var slot_key: [32]u8 = undefined;
                std.mem.writeInt(u256, &slot_key, slot_changes.key, .big);
                var slot_hash: [32]u8 = undefined;
                std.crypto.hash.sha3.Keccak256.hash(&slot_key, &slot_hash, .{});

                if (!self.isStorageFetched(addr_hash, slot_hash)) continue;
                try self.eth_db.writeStorage(txn, addr_hash, slot_hash, slot_changes.changes[slot_changes.changes.len - 1].value);
            }

            if (changes.storage_changes.len > 0) {
                self.requestAccountRange(
                    self.free_snap_requests.pop() orelse return account_index,
                    self.state_heal.?.next_pivot.state_root,
                    addr_hash,
                    addr_hash,
                );
            } else {
                var updated_account = try self.eth_db.readAccount(self.allocator, txn, addr_hash) orelse types.EmptyAccount;
                if (changes.balance_changes.len > 0)
                    updated_account.balance = changes.balance_changes[changes.balance_changes.len - 1].balance;
                if (changes.nonce_changes.len > 0)
                    updated_account.nonce = changes.nonce_changes[changes.nonce_changes.len - 1].nonce;
                if (changes.code_changes.len > 0) {
                    updated_account.code_hash = code_hash;
                }
                if (updated_account.isEmpty()) {
                    try self.eth_db.deleteAccount(txn, addr_hash);
                } else try self.eth_db.writeAccount(self.allocator, txn, addr_hash, updated_account);
            }
        }

        return bal.len;
    }

    fn isStorageFetched(self: *Self, account_hash: [32]u8, slot_hash: [32]u8) bool {
        std.debug.assert(self.state_heal != null);
        const state = &self.state.?;
        if (!state.accounts_done) return false;
        if (!state.storage_and_fetch_initiated and
            std.mem.order(u8, &account_hash, &state.storage_fetch_head) != .lt) return false;

        for (self.stashed_snap_requests) |request| {
            if (request.msg != .get_storage_ranges) continue;
            const storage_request = request.msg.get_storage_ranges;
            for (storage_request.account_hashes, 0..) |requested_account, index| {
                if (std.meta.eql(requested_account, account_hash))
                    return index == 0 and std.mem.order(u8, &slot_hash, &storage_request.starting_hash) == .lt;
            }
        }
        return true;
    }

    fn handleStorage(self: *Self, req: *Request(snap.Message), response: *const snap.StorageRanges) !void {
        const allocator = self.snap_arena.allocator();
        const request = &req.msg.get_storage_ranges;
        const requested_accounts = request.account_hashes;

        var proof: trie.NodesHashMap = .empty;
        if (response.proof.len > 0) {
            try proof.ensureTotalCapacity(allocator, @intCast(response.proof.len));
            for (response.proof) |node| {
                var h: [32]u8 align(8) = undefined;
                std.crypto.hash.sha3.Keccak256.hash(node, &h, .{});
                try proof.put(allocator, h, node);
            }
        }

        const txn = try self.eth_db.kv_store.transaction_rw();
        errdefer _ = txn.abort() catch |e| {
            log.err("failed to abort txn {}", .{e});
        };

        var verified: usize = 0;
        var continue_from: ?[32]u8 = null;
        for (response.slots[0..@min(response.slots.len, requested_accounts.len)], 0..) |slots, index| {
            const account_hash = requested_accounts[index];
            const account = try self.eth_db.readAccount(allocator, txn, account_hash) orelse break;
            const origin: [32]u8 = if (index == 0) request.starting_hash else @splat(0);
            const is_last = index + 1 == response.slots.len;

            const keys = try allocator.alloc([32]u8, slots.len);
            const values = try allocator.alloc([]const u8, slots.len);
            for (slots, 0..) |slot, slot_index| {
                keys[slot_index] = slot.hash;
                values[slot_index] = slot.data;
            }

            const has_more = verifyRangeProof(
                allocator,
                account.storage_hash,
                origin,
                keys,
                values,
                if (is_last and response.proof.len > 0) &proof else null,
            ) catch break;

            try self.eth_db.insertStorage(txn, account_hash, keys, values);
            verified += 1;
            if (has_more) {
                continue_from = origin;
                if (keys.len > 0)
                    std.mem.writeInt(
                        u256,
                        &continue_from.?,
                        std.mem.readInt(u256, &keys[keys.len - 1], .big) + 1,
                        .big,
                    );
                break;
            }
        }
        try txn.commit();

        var remaining: usize = 0;
        var next_start: [32]u8 = if (verified == 0) request.starting_hash else @splat(0);
        if (continue_from) |slot| {
            requested_accounts[0] = requested_accounts[verified - 1];
            next_start = slot;
            remaining = 1;
        }
        const unserved = requested_accounts[verified..];
        std.mem.copyForwards([32]u8, requested_accounts[remaining..][0..unserved.len], unserved);
        remaining += unserved.len;

        if (remaining > 0) {
            request.account_hashes = requested_accounts[0..remaining];
            request.starting_hash = next_start;
            self.sendSnapRequest(req) catch {};
        } else {
            self.allocator.free(@as([][32]u8, requested_accounts.ptr[0..batch_storage_code_req_size]));
            self.progress.storage_keyspace +|= req.keyspace[1] - req.keyspace[0];
            self.free_snap_requests.push(req);
        }
    }

    fn handleCodes(self: *Self, req: *Request(snap.Message), codes: snap.ByteCodes) !void {
        const txn = try self.eth_db.kv_store.transaction_rw();
        defer txn.commit() catch unreachable;
        const table = self.eth_db.kv_store.table(txn, .codes);

        const requested_hashes = req.msg.get_byte_codes.hashes;

        var retry_count: usize = 0;
        var next_hash_index: usize = 0;
        for (codes.bytecodes) |code| {
            var code_hash: [32]u8 = undefined;
            std.crypto.hash.sha3.Keccak256.hash(code, &code_hash, .{});

            while (next_hash_index < requested_hashes.len and !std.meta.eql(requested_hashes[next_hash_index], code_hash)) : (next_hash_index += 1) {
                requested_hashes[retry_count] = requested_hashes[next_hash_index];
                retry_count += 1;
            }
            if (next_hash_index == requested_hashes.len) break;

            table.set(&code_hash, code, .Create) catch |e| {
                if (e != lmdbx.Error.MDBX_KEYEXIST) return e;
            };
            next_hash_index += 1;
        }
        const unserved = requested_hashes[next_hash_index..];
        std.mem.copyForwards([32]u8, requested_hashes[retry_count..][0..unserved.len], unserved);
        retry_count += unserved.len;

        if (retry_count > 0) {
            self.requestCodes(req, requested_hashes[0..retry_count]);
        } else {
            self.allocator.free(@as([][32]u8, requested_hashes.ptr[0..batch_storage_code_req_size]));
            self.progress.code_keyspace +|= req.keyspace[1] - req.keyspace[0];
            self.free_snap_requests.push(req);
        }
    }

    fn logProgress(self: *Self) void {
        const now = std.Io.Clock.now(.real, self.io);
        if (self.progress.last_log) |last| {
            if (last.durationTo(now).nanoseconds < progress_log_interval.nanoseconds) return;
        }
        self.progress.last_log = now;

        if (self.eth_provider.server) |server| {
            log.info("peers: {}/{} connections, eth {}, snap {}; dials {} (failed {}), inbound {}, handshakes {}, disconnects {}", .{
                server.connectionCount(),
                rlpx.Server.max_peers,
                self.eth_provider.peerCount(),
                self.snap_provider.peerCount(),
                server.stats.dials.load(.monotonic),
                server.stats.failed_dials.load(.monotonic),
                server.stats.inbound.load(.monotonic),
                server.stats.handshakes.load(.monotonic),
                server.stats.disconnects.load(.monotonic),
            });
        }

        const target = self.syncTarget();
        const head_number = if (self.bc.head()) |head| head.number else |_| target.number;
        if (target.number > head_number) {
            const total_headers = target.number - target.cutoff_number + 1;
            log.info("header download: {d:.2}% ({}/{} headers), target {}, inflight requests {}", .{
                @as(f64, @floatFromInt(self.progress.headers)) / @as(f64, @floatFromInt(total_headers)) * 100,
                self.progress.headers,
                total_headers,
                target.number,
                self.inflight_eth_requests.inner.len(),
            });
        }
        if (self.state) |state| {
            log.info("state download: pivot {}, accounts {d:.2}% (done: {}), storage {d:.2}%, codes {d:.2}%, inflight requests {}, healing {}", .{
                state.pivot.number,
                keyspacePercent(self.progress.account_keyspace),
                state.accounts_done,
                keyspacePercent(self.progress.storage_keyspace),
                keyspacePercent(self.progress.code_keyspace),
                self.inflight_snap_requests.inner.len(),
                self.state_heal != null,
            });
        }
        if (self.state_heal) |state_heal| {
            const healed = state_heal.next_pivot.number - 1 - state_heal.start_number;
            const total = state_heal.target_pivot.number - state_heal.start_number;
            const bal_status: []const u8, const applied: usize, const touched: usize = if (state_heal.bal) |bal|
                .{ "applying", bal.resume_index, bal.parsed.len }
            else if (state_heal.bal_requested)
                .{ "requested", 0, 0 }
            else
                .{ "not requested", 0, 0 };
            log.info("state heal: block {} ({}/{} healed, {}s elapsed), bal {s} ({}/{} accounts), inflight snap {}, pending snap {}, inflight eth {}", .{
                state_heal.next_pivot.number,
                healed,
                total,
                state_heal.started_at.durationTo(now).toSeconds(),
                bal_status,
                applied,
                touched,
                self.inflight_snap_requests.inner.len(),
                self.pending_snap_requests.inner.len(),
                self.inflight_eth_requests.inner.len(),
            });
        }
    }

    fn keyspacePercent(covered: u256) f64 {
        return @as(f64, @floatFromInt(@as(u64, @truncate(covered >> 192)))) / std.math.pow(f64, 2, 64) * 100;
    }

    fn matchRequest(
        self: *Self,
        comptime Message: type,
        provider: anytype,
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
                provider.observeDelay(peer, request_tag, request.elem.sent_at.untilNow(self.io, .real));
                list.inner.remove(node);
                node.next = null;
                node.prev = null;
                return &request.elem;
            }

            current_node = next_node;
        }
        return null;
    }

    fn readHeader(self: *Self, number: u64) !?types.BlockHeader {
        return try self.readDownladedHeader(number) orelse self.bc.readHeader(number);
    }

    fn headerIsInTargetChain(self: *Self, header: types.BlockHeader) !bool {
        const target = self.syncTarget();
        const head = try self.readHeader(target.number) orelse return error.Maybe;
        if (!std.mem.eql(u8, &target.hash, &head.hash())) return error.Maybe;

        const stored_header = try self.readHeader(header.number) orelse return false;
        if (!std.mem.eql(u8, &stored_header.hash(), &header.hash())) return false;

        for (header.number + 1..head.number) |block_number| {
            _ = try self.readHeader(block_number) orelse return error.Maybe;
        }
        return true;
    }
};

const invalid_peer: rlpx.Server.PeerId = .{
    .peer_index = std.math.maxInt(usize),
    .peer_epoch = std.math.maxInt(usize),
};

fn PeerFilter(comptime Message: type) type {
    return struct {
        downloader: *Downloader,
        min_height: ?u64,
        inflight: [rlpx.Server.max_peers]struct { epoch: usize = 0, count: usize = 0 } = @splat(.{}),

        fn init(downloader: *Downloader, inflight: *List(Request(Message)), min_height: ?u64) @This() {
            var self: @This() = .{ .downloader = downloader, .min_height = min_height };
            var current_node = inflight.inner.first;
            while (current_node) |node| : (current_node = node.next) {
                const request: *List(Request(Message)).Node = @alignCast(@fieldParentPtr("node", node));
                const peer = request.elem.peer;
                const slot = &self.inflight[peer.peer_index];
                if (peer.peer_epoch > slot.epoch) slot.* = .{ .epoch = peer.peer_epoch };
                if (peer.peer_epoch == slot.epoch) slot.count += 1;
            }
            return self;
        }

        pub fn validPeer(self: *const @This(), peer_id: rlpx.Server.PeerId) bool {
            if (self.min_height) |min_height| {
                const peer_range = self.downloader.peer_ranges[peer_id.peer_index] orelse return false;
                if (peer_range.id.peer_epoch != peer_id.peer_epoch or min_height > peer_range.range.latest_block) return false;
            }

            const slot = self.inflight[peer_id.peer_index];
            return slot.epoch != peer_id.peer_epoch or slot.count < max_inflight_requests_per_peer;
        }
    };
}

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
