// Copyright (c) 2025-2026 zevm authors
// SPDX-License-Identifier: MIT OR Apache-2.0

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
const prom = @import("metrics");

const verifyRangeProof = @import("../trie/range_proof.zig").verifyRangeProof;
const EthDb = @import("../db/eth.zig").Eth;
const List = @import("../free_list.zig").List;
const max_inflight_requests = 100;
const max_inflight_requests_per_peer = 2;
const header_persist_chunk = 1024;
const batch_storage_code_req_size = 256;
const min_split_range = std.math.maxInt(u256) / (1 << 16);
const progress_log_interval: std.Io.Duration = .fromSeconds(8);
const arena_retain_limit = (32 << 20) - 64;
const max_snap_flush_queue_bytes = 2048 << 20;
const max_snap_flush_seconds = 0.5;
const expected_code_count = 20_000_000;

const log = std.log.scoped(.downloader);

pub const Downloader = struct {
    const Self = @This();

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
    validating_eth_requests: List(Request(eth.Message)) = .{},

    snap_arena: std.heap.ArenaAllocator,
    snap_provider: *snap.Provider,
    free_snap_requests: List(Request(snap.Message)),
    inflight_snap_requests: List(Request(snap.Message)) = .{},
    pending_snap_requests: List(Request(snap.Message)) = .{},
    stashed_snap_requests: []Request(snap.Message),
    validating_snap_requests: List(Request(snap.Message)) = .{},
    snap_flush_queue: List(QueuedSnapFlush) = .{},
    snap_flush_queue_bytes: usize = 0,

    validated_responses: std.Io.Queue(ValidatedResponse),
    validation_group: std.Io.Group = .init,

    sync_target: SyncTarget,
    sync_target_mutex: std.Io.Mutex = .init,
    header: ?struct {
        requested_header_head: u64,
        requested_header_tail: u64,
    } = null,
    state: ?struct {
        pivot: types.BlockHeader,

        phase: enum {
            accounts,
            storage,
            codes,
        } = .accounts,

        account_fetch_head: u256 = 0,
        account_fetch_step: u256 = 0,
        storage_fetch_head: [32]u8 = @splat(0),
        code_hashes: std.AutoArrayHashMapUnmanaged([32]u8, void) = .empty,
        code_fetch_head: usize = 0,
    } = null,
    state_heal: ?struct {
        next_pivot: types.BlockHeader,
        target_pivot: types.BlockHeader,
        start_number: u64,
        started_at: std.Io.Timestamp,

        bal_requested: bool = false,
        bal_applied: bool = false,
        pivot_hash_buf: [1][32]u8 = undefined,
        stale_storage_roots: std.AutoArrayHashMapUnmanaged([32]u8, void) = .empty,
    } = null,
    metrics: Metrics,
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
            .metrics = try .init(allocator, io),
            .sync_target = .{
                .number = head.number,
                .hash = head.hash,
                .cutoff_number = head.number,
                .cutoff_hash = head.hash,
            },
            .validated_responses = .init(try allocator.alloc(ValidatedResponse, 2 * max_inflight_requests)),
        };
    }

    pub fn run(self: *Self) !void {
        const tag = enum(u8) { eth, snap, validated, tick };
        const msg = union(tag) {
            eth: @typeInfo(@TypeOf(eth.Provider.next)).@"fn".return_type.?,
            snap: @typeInfo(@TypeOf(snap.Provider.next)).@"fn".return_type.?,
            validated: @typeInfo(@TypeOf(std.Io.Queue(ValidatedResponse).getOne)).@"fn".return_type.?,
            tick: @typeInfo(@TypeOf(std.Io.sleep)).@"fn".return_type.?,
        };

        var buf: [4]msg = undefined;
        var select: std.Io.Select(msg) = .init(self.io, &buf);
        defer self.validation_group.cancel(self.io);

        try select.concurrent(.eth, eth.Provider.next, .{ self.eth_provider, self.io, self.eth_arena.allocator(), self.allocator });
        try select.concurrent(.snap, snap.Provider.next, .{ self.snap_provider, self.io, self.snap_arena.allocator(), self.allocator });
        try select.concurrent(.validated, std.Io.Queue(ValidatedResponse).getOne, .{ &self.validated_responses, self.io });
        try select.concurrent(.tick, std.Io.sleep, .{ self.io, .fromSeconds(1), .real });

        var busy_start = std.Io.Timestamp.now(self.io, .awake);
        while (true) {
            const wait_start = std.Io.Timestamp.now(self.io, .awake);
            self.metrics.loop_busy_seconds.incrBy(secondsSince(self.io, busy_start));
            const event = try select.await();
            busy_start = std.Io.Timestamp.now(self.io, .awake);
            self.metrics.loop_wait_seconds.incrBy(secondsSince(self.io, wait_start));

            switch (event) {
                .eth => |res| {
                    defer select.concurrent(.eth, eth.Provider.next, .{ self.eth_provider, self.io, self.eth_arena.allocator(), self.allocator }) catch |e| std.debug.panic("downloader: failed to spawn task: {}", .{e});
                    const received_message = res catch {
                        _ = self.eth_arena.reset(.{ .retain_with_limit = arena_retain_limit });
                        continue;
                    };
                    if (!try self.handleEth(received_message)) {
                        self.allocator.free(received_message.read.payload);
                        _ = self.eth_arena.reset(.{ .retain_with_limit = arena_retain_limit });
                    }
                    self.observeHandle(@tagName(received_message.msg), busy_start);
                },
                .snap => |res| {
                    defer select.concurrent(.snap, snap.Provider.next, .{ self.snap_provider, self.io, self.snap_arena.allocator(), self.allocator }) catch |e| std.debug.panic("downloader: failed to spawn task: {}", .{e});
                    const received_message = res catch {
                        _ = self.snap_arena.reset(.{ .retain_with_limit = arena_retain_limit });
                        continue;
                    };
                    if (!try self.handleSnap(received_message)) {
                        self.allocator.free(received_message.read.payload);
                        _ = self.snap_arena.reset(.{ .retain_with_limit = arena_retain_limit });
                    }
                    self.observeHandle(@tagName(received_message.msg), busy_start);
                },
                .validated => |res| {
                    defer select.concurrent(.validated, std.Io.Queue(ValidatedResponse).getOne, .{ &self.validated_responses, self.io }) catch |e| std.debug.panic("downloader: failed to spawn task: {}", .{e});
                    const validated = try res;
                    try self.handleValidated(validated);
                    self.observeHandle(validated.resp.msgName(), busy_start);
                },
                .tick => {
                    defer select.concurrent(.tick, std.Io.sleep, .{ self.io, .fromSeconds(1), .real }) catch |e| std.debug.panic("downloader: failed to spawn task: {}", .{e});
                    try self.handleTick();
                    self.observeHandle("tick", busy_start);
                },
            }
        }
    }

    fn handleTick(self: *Self) !void {
        self.updateMetrics();
        self.logProgress();
        if (self.header != null) {
            try self.advanceHeaderDownload();
        }
        try self.drainSnapFlushQueue();
        if (self.state != null) {
            try self.updatePivot();
            try self.advanceStateDownload();
        }
        if (self.state_heal != null) {
            try self.advanceStateHeal();
        }
        try self.checkEthRequestTimeouts();
        try self.checkSnapRequestTimeouts();
        self.drainPendingEthRequests();
        self.drainPendingSnapRequests();
    }

    fn handleEth(self: *Self, received: eth.Provider.ParsedMessage) !bool {
        const peer = received.read.peer;
        var matched: ?*Request(eth.Message) = null;
        switch (received.msg) {
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
            .block_headers => |headers| matched = self.matchRequest(eth.Message, self.eth_provider, &self.inflight_eth_requests, peer, headers.request_id, .get_block_headers),
            .block_access_list => |access_lists| matched = self.matchRequest(eth.Message, self.eth_provider, &self.inflight_eth_requests, peer, access_lists.request_id, .get_block_access_list),
            else => {},
        }
        if (matched) |req| {
            self.validating_eth_requests.push(req);
            try self.startValidation(&self.eth_arena, .{ .eth = .{ .msg = received, .req = req } });
        }
        self.drainPendingEthRequests();
        return matched != null;
    }

    fn handleSnap(self: *Self, received: snap.Provider.ParsedMessage) !bool {
        const peer = received.read.peer;
        const matched = switch (received.msg) {
            .account_range => |account_range| self.matchRequest(snap.Message, self.snap_provider, &self.inflight_snap_requests, peer, account_range.id, .get_account_range),
            .storage_ranges => |storage_ranges| self.matchRequest(snap.Message, self.snap_provider, &self.inflight_snap_requests, peer, storage_ranges.id, .get_storage_ranges),
            .byte_codes => |byte_codes| self.matchRequest(snap.Message, self.snap_provider, &self.inflight_snap_requests, peer, byte_codes.id, .get_byte_codes),
            else => null,
        };
        if (matched) |req| {
            insertRequest(&self.validating_snap_requests, req, .back);
            try self.startValidation(&self.snap_arena, .{ .snap = .{ .msg = received, .req = req } });
        }
        self.drainPendingSnapRequests();
        return matched != null;
    }

    fn startValidation(self: *Self, arena: *std.heap.ArenaAllocator, response: @FieldType(ValidatedResponse, "resp")) !void {
        defer arena.* = .init(self.allocator);
        self.validation_group.concurrent(self.io, validate, .{ self, arena.*, response }) catch validate(self, arena.*, response);
    }

    fn validate(self: *Self, arena: std.heap.ArenaAllocator, response: @FieldType(ValidatedResponse, "resp")) void {
        const start = std.Io.Timestamp.now(self.io, .awake);
        var gpa = arena;
        const allocator = gpa.allocator();
        const outcome = switch (response) {
            .eth => |*resp| switch (resp.msg.msg) {
                .block_headers => |headers| validateHeaders(allocator, resp.req.msg.get_block_headers, headers),
                .block_access_list => |access_lists| validateBal(allocator, access_lists),
                else => unreachable,
            },
            .snap => |*resp| switch (resp.msg.msg) {
                .account_range => |*account_range| self.verifyAccounts(allocator, resp.req.msg.get_account_range, account_range),
                .storage_ranges => |*storage_ranges| self.verifyStorage(allocator, resp.req.msg.get_storage_ranges, resp.req.storage_roots, storage_ranges),
                .byte_codes => |byte_codes| hashCodes(allocator, byte_codes),
                else => unreachable,
            },
        };

        self.metrics.verify_seconds.observe(.{ .msg = response.msgName() }, secondsSince(self.io, start)) catch {};
        self.validated_responses.putOneUncancelable(self.io, .{ .arena = gpa, .resp = response, .outcome = outcome }) catch unreachable;
    }

    fn handleValidated(self: *Self, validated: ValidatedResponse) !void {
        if (validated.outcome) |_| {} else |err| switch (validated.resp) {
            inline else => |resp, proto| {
                log.debug("dropping peer {} for an invalid {s}: {}", .{ resp.req.peer.peer_index, validated.resp.msgName(), err });
                const provider = if (proto == .eth) self.eth_provider else self.snap_provider;
                provider.disconnect(resp.req.peer, err);
            },
        }

        switch (validated.resp) {
            .eth => |*resp| {
                defer validated.deinit(self.allocator);

                self.validating_eth_requests.remove(resp.req);
                switch (resp.msg.msg) {
                    .block_headers => try self.handleHeaders(resp.req, validated.outcome),
                    .block_access_list => try self.handleBals(resp.req, validated.outcome),
                    else => unreachable,
                }
                self.drainPendingEthRequests();
            },
            .snap => |*resp| {
                {
                    errdefer validated.deinit(self.allocator);
                    self.validating_snap_requests.remove(resp.req);
                    switch (resp.msg.msg) {
                        .account_range => try self.handleAccounts(resp.req, validated.outcome),
                        .storage_ranges => try self.handleStorage(resp.req, validated.outcome),
                        .byte_codes => try self.handleCodes(resp.req, validated.outcome),
                        else => unreachable,
                    }
                }
                try self.queueSnapFlush(validated);
                try self.drainSnapFlushQueue();

                self.drainPendingSnapRequests();
                if (self.state != null)
                    try self.advanceStateDownload();
                if (self.state_heal != null)
                    try self.advanceStateHeal();
            },
        }
    }

    fn queueSnapFlush(self: *Self, validated: ValidatedResponse) !void {
        const outcome = validated.outcome catch return validated.deinit(self.allocator);
        var flush: QueuedSnapFlush = .{ .arena = validated.arena, .response = validated.resp.snap.msg, .validation_outcome = outcome };
        const node = flush.arena.allocator().create(List(QueuedSnapFlush).Node) catch |err| {
            flush.deinit(self.allocator);
            return err;
        };
        node.elem = flush;
        self.snap_flush_queue.insertSorted(&node.elem, QueuedSnapFlush.lessThan);
        self.snap_flush_queue_bytes += node.elem.size();
    }

    fn drainSnapFlushQueue(self: *Self) !void {
        const start = std.Io.Timestamp.now(self.io, .awake);
        var current_node = self.snap_flush_queue.inner.first;
        while (current_node) |list_node| {
            if (secondsSince(self.io, start) > max_snap_flush_seconds) return;
            current_node = list_node.next;
            const flush = &@as(*List(QueuedSnapFlush).Node, @alignCast(@fieldParentPtr("node", list_node))).elem;
            if (self.hasPrecedingSnapRequest(flush)) continue;

            self.snap_flush_queue.remove(flush);
            self.snap_flush_queue_bytes -= flush.size();
            self.metrics.snap_flushed_bytes.incrBy(flush.size());
            defer flush.deinit(self.allocator);
            switch (flush.response.msg) {
                .account_range => |*account_range| try self.persistAccounts(flush.validation_outcome.accounts, account_range),
                .storage_ranges => try self.persistStorage(flush.validation_outcome.storage),
                .byte_codes => |byte_codes| try self.persistCodes(flush.validation_outcome.codes, byte_codes.bytecodes),
                else => unreachable,
            }
        }
    }

    fn hasPrecedingSnapRequest(self: *Self, flush: *const QueuedSnapFlush) bool {
        for ([_]*List(Request(snap.Message)){ &self.pending_snap_requests, &self.inflight_snap_requests, &self.validating_snap_requests }) |list| {
            var current_node = list.inner.first;
            while (current_node) |list_node| : (current_node = list_node.next) {
                const request: *List(Request(snap.Message)).Node = @alignCast(@fieldParentPtr("node", list_node));
                if (flush.isPrecededBy(request.elem.msg, false)) return true;
            }
        }
        return false;
    }

    fn validateHeaders(allocator: std.mem.Allocator, request: eth.GetBlockHeaders, response: eth.BlockHeaders) !ValidationOutcome {
        if (response.rlps.len == 0) return .{ .headers = .{ .hashes = &.{}, .headers = &.{} } };

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

        return .{ .headers = .{ .hashes = hashes, .headers = headers } };
    }

    fn validateBal(allocator: std.mem.Allocator, response: eth.BlockAccessLists) !ValidationOutcome {
        if (response.rlps.len == 0) return error.EmptyResponse;
        var hash: [32]u8 = undefined;
        std.crypto.hash.sha3.Keccak256.hash(response.rlps[0].value, &hash, .{});
        var parsed: types.BlockAccessLists = undefined;
        _ = try rlp.deserialize(types.BlockAccessLists, allocator, response.rlps[0].value, &parsed);
        return .{ .bal = .{ .hash = hash, .parsed = parsed } };
    }

    fn verifyAccounts(self: *Self, allocator: std.mem.Allocator, request: snap.GetAccountRange, response: *const snap.AccountRange) !ValidationOutcome {
        if (response.accounts.len == 0 and response.proof.len == 0) return error.EmptyAccountRange;
        var scratch_arena = std.heap.ArenaAllocator.init(self.allocator);
        defer scratch_arena.deinit();
        const scratch = scratch_arena.allocator();
        const hashes = try allocator.alloc([32]u8, response.accounts.len);
        const accounts = try scratch.alloc([]const u8, response.accounts.len);
        var code_hashes = try allocator.alloc([32]u8, response.accounts.len);
        code_hashes.len = 0;
        for (response.accounts, 0..) |elem, index| {
            hashes[index] = elem.hash;

            var slim_account: snap.SlimAccount = undefined;
            _ = try rlp.deserialize(snap.SlimAccount, scratch, elem.account.value, &slim_account);
            if (slim_account.code_hash.len == 32 and !std.mem.eql(u8, slim_account.code_hash, &types.empty_code_hash) and
                std.mem.order(u8, &elem.hash, &request.limit) != .gt)
            {
                code_hashes.len += 1;
                code_hashes[code_hashes.len - 1] = slim_account.code_hash[0..32].*;
            }

            var list = std.array_list.Managed(u8).init(scratch);
            try rlp.serialize(types.Account, scratch, slimToFullAccount(slim_account), &list);
            accounts[index] = try list.toOwnedSlice();
        }

        const proof = try proofNodes(scratch, response.proof);
        const has_more = try verifyRangeProof(
            scratch,
            request.root,
            request.origin,
            hashes,
            accounts,
            if (response.proof.len > 0) &proof else null,
            try scratch.create([trie.Trie.stack_size]u8),
        );
        const served = countBelowLimit(hashes, request.limit);
        return .{ .accounts = .{
            .origin = request.origin,
            .limit = request.limit,
            .hashes = hashes[0..served],
            .code_hashes = code_hashes,
            .has_more = has_more and served == hashes.len,
        } };
    }

    fn verifyStorage(
        self: *Self,
        allocator: std.mem.Allocator,
        request: snap.GetStorageRanges,
        storage_roots: []const [32]u8,
        response: *const snap.StorageRanges,
    ) !ValidationOutcome {
        if (response.slots.len == 0 and response.proof.len == 0) return error.EmptyStorageRanges;
        var scratch_arena = std.heap.ArenaAllocator.init(self.allocator);
        defer scratch_arena.deinit();
        const scratch = scratch_arena.allocator();
        const proof = try proofNodes(scratch, response.proof);
        const stack_buffer = try scratch.create([trie.Trie.stack_size]u8);

        const served = response.slots[0..@min(response.slots.len, request.account_hashes.len)];
        var result: VerifiedStorage = .{
            .chunk = isStorageChunk(request),
            .keys = try allocator.alloc([][32]u8, @max(served.len, 1)),
            .values = try allocator.alloc([][]const u8, @max(served.len, 1)),
        };
        var verified: usize = 0;
        if (served.len == 0 and request.account_hashes.len > 0) {
            // without slots, the proof has to show the first account has none from the starting to u256.max
            _ = try verifyRangeProof(scratch, storage_roots[0], request.starting_hash, &.{}, &.{}, &proof, stack_buffer);
            result.keys[0] = &.{};
            result.values[0] = &.{};
            verified = 1;
        }
        for (served, 0..) |slots, index| {
            const origin: [32]u8 = if (index == 0) request.starting_hash else @splat(0);
            const is_last = index + 1 == response.slots.len;

            const keys = try allocator.alloc([32]u8, slots.len);
            const values = try allocator.alloc([]const u8, slots.len);
            for (slots, 0..) |slot, slot_index| {
                keys[slot_index] = slot.hash;
                values[slot_index] = slot.data;
            }

            const has_more = verifyRangeProof(
                scratch,
                storage_roots[index],
                origin,
                keys,
                values,
                if (is_last and response.proof.len > 0) &proof else null,
                stack_buffer,
            ) catch break;

            const served_slots = if (index + 1 == request.account_hashes.len)
                countBelowLimit(keys, request.limit_hash)
            else
                keys.len;
            result.keys[index] = keys[0..served_slots];
            result.values[index] = values[0..served_slots];
            verified = index + 1;
            if (has_more and served_slots == keys.len) {
                result.continue_from_slot = origin;
                if (keys.len > 0)
                    std.mem.writeInt(
                        u256,
                        &result.continue_from_slot.?,
                        std.mem.readInt(u256, &keys[keys.len - 1], .big) + 1,
                        .big,
                    );
                break;
            }
        }
        result.account_hashes = try allocator.dupe([32]u8, request.account_hashes[0..verified]);
        result.keys = result.keys[0..verified];
        result.values = result.values[0..verified];
        return .{ .storage = result };
    }

    fn countBelowLimit(keys: []const [32]u8, limit: [32]u8) usize {
        for (keys, 0..) |key, index| {
            if (std.mem.order(u8, &key, &limit) == .gt) return index;
        }
        return keys.len;
    }

    fn hashCodes(allocator: std.mem.Allocator, response: snap.ByteCodes) !ValidationOutcome {
        const hashes = try allocator.alloc([32]u8, response.bytecodes.len);
        for (response.bytecodes, hashes) |code, *hash|
            std.crypto.hash.sha3.Keccak256.hash(code, hash, .{});
        return .{ .codes = hashes };
    }

    fn proofNodes(allocator: std.mem.Allocator, nodes: []const []const u8) !trie.NodesHashMap {
        var proof: trie.NodesHashMap = .empty;
        if (nodes.len > 0) {
            try proof.ensureTotalCapacity(allocator, @intCast(nodes.len));
            for (nodes) |node| {
                var h: [32]u8 align(8) = undefined;
                std.crypto.hash.sha3.Keccak256.hash(node, &h, .{});
                try proof.put(allocator, h, node);
            }
        }
        return proof;
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
            try self.state.?.code_hashes.ensureTotalCapacity(std.heap.page_allocator, expected_code_count);
        }

        try self.updatePivot();
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
        self.metrics.requests_sent.incr(.{ .msg = @tagName(req.msg) }) catch {};
        req.deadline = sent_at.addDuration(try provider.timeoutFor(req.peer, std.meta.activeTag(req.msg)));
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
                const delay = request.elem.sent_at.untilNow(self.io, .real);
                provider.observeDelay(peer, request_tag, delay);
                self.metrics.response_seconds.observe(
                    .{ .msg = @tagName(request_tag) },
                    @as(f64, @floatFromInt(delay.toNanoseconds())) / std.time.ns_per_s,
                ) catch {};
                list.inner.remove(node);
                node.next = null;
                node.prev = null;
                return &request.elem;
            }

            current_node = next_node;
        }
        return null;
    }

    fn drainPendingRequests(self: *Self, pending: anytype, inflight: anytype, send_fn: anytype) void {
        while (pending.pop()) |req| {
            send_fn(self, req) catch return insertRequest(pending, req, .front);
            insertRequest(inflight, req, .back);
        }
    }

    fn insertRequest(list: anytype, req: anytype, comptime at: enum { front, back }) void {
        if (@TypeOf(list) == *List(Request(snap.Message))) return list.insertSorted(req, Request(snap.Message).lessThan);
        switch (at) {
            .front => list.prepend(req),
            .back => list.push(req),
        }
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
                    self.metrics.request_timeouts.incr(.{ .msg = @tagName(request.elem.msg) }) catch {};
                    log.debug("{t} request {} to {} timed out after {}ms (timeout {}ms)", .{
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
                insertRequest(pending, &request.elem, .front);
            }

            current_node = next_node;
        }
    }

    fn pickEthPeer(self: *Self, msg: eth.Message) !rlpx.Server.PeerId {
        switch (msg) {
            .get_block_headers => |header_req| {
                const allowed_height_gap = 16;
                const height = switch (header_req.range.origin) {
                    .number => |number| number -| allowed_height_gap,
                    .hash => self.syncTarget().number -| allowed_height_gap,
                };
                return self.eth_provider.pickRandomPeer(PeerFilter(eth.Message).init(self, &self.inflight_eth_requests, height));
            },
            else => {},
        }
        return self.eth_provider.pickRandomPeer(PeerFilter(eth.Message).init(self, &self.inflight_eth_requests, null));
    }

    fn sendEthRequest(self: *Self, req: *Request(eth.Message), urgent: bool) void {
        if (urgent) self.pending_eth_requests.prepend(req) else self.pending_eth_requests.push(req);
        self.drainPendingEthRequests();
    }

    fn reissueEthRequest(self: *Self, req: *Request(eth.Message)) !void {
        return self.sendRequest(self.eth_provider, Self.pickEthPeer, req);
    }

    fn popFreeEthRequest(self: *Self) ?*Request(eth.Message) {
        if (!self.pending_eth_requests.empty()) return null;
        return self.free_eth_requests.pop();
    }

    fn drainPendingEthRequests(self: *Self) void {
        drainPendingRequests(self, &self.pending_eth_requests, &self.inflight_eth_requests, Self.reissueEthRequest);
    }

    fn checkEthRequestTimeouts(self: *Self) !void {
        self.checkRequestTimeouts(eth.Message, &self.inflight_eth_requests, &self.pending_eth_requests, self.eth_provider);
        self.drainPendingEthRequests();
    }

    fn pickSnapPeer(self: *Self, msg: snap.Message) !rlpx.Server.PeerId {
        return self.snap_provider.pickFastestPeer(std.meta.activeTag(msg), PeerFilter(snap.Message).init(
            self,
            &self.inflight_snap_requests,
            self.state.?.pivot.number,
        ));
    }

    fn sendSnapRequest(self: *Self, req: *Request(snap.Message)) !void {
        insertRequest(&self.pending_snap_requests, req, .back);
        self.drainPendingSnapRequests();
    }

    fn reissueSnapRequest(self: *Self, req: *Request(snap.Message)) !void {
        if (self.snapFlushQueueFull()) {
            const head_node = self.snap_flush_queue.inner.first orelse return error.SnapFlushQueueFull;
            const head = &@as(*List(QueuedSnapFlush).Node, @alignCast(@fieldParentPtr("node", head_node))).elem;
            if (!head.isPrecededBy(req.msg, true)) return error.SnapFlushQueueFull;
        }
        return self.sendRequest(self.snap_provider, Self.pickSnapPeer, req);
    }

    fn snapFlushQueueFull(self: *Self) bool {
        if (self.state_heal) |state_heal| if (!state_heal.bal_requested) return true;
        return self.snap_flush_queue_bytes > max_snap_flush_queue_bytes;
    }

    fn popFreeSnapRequest(self: *Self) ?*Request(snap.Message) {
        if (!self.pending_snap_requests.empty()) return null;
        return self.free_snap_requests.pop();
    }

    fn drainPendingSnapRequests(self: *Self) void {
        drainPendingRequests(self, &self.pending_snap_requests, &self.inflight_snap_requests, Self.reissueSnapRequest);
    }

    fn checkSnapRequestTimeouts(self: *Self) !void {
        self.checkRequestTimeouts(snap.Message, &self.inflight_snap_requests, &self.pending_snap_requests, self.snap_provider);
        self.drainPendingSnapRequests();
    }

    fn stashSnapRequests(self: *Self) void {
        while (self.inflight_snap_requests.pop() orelse self.pending_snap_requests.pop()) |node| {
            self.stashed_snap_requests.len += 1;
            self.stashed_snap_requests[self.stashed_snap_requests.len - 1] = node.*;
            self.free_snap_requests.push(node);
        }
    }

    fn popSnapRequests(self: *Self) !void {
        std.debug.assert(self.inflight_snap_requests.empty() and self.pending_snap_requests.empty());

        const pivot_root = self.state.?.pivot.state_root;
        const txn = try self.eth_db.kv_store.transaction_ro();
        defer txn.abort() catch unreachable;

        for (self.stashed_snap_requests) |stashed_req| {
            const req = self.free_snap_requests.pop() orelse unreachable;
            req.* = stashed_req;
            switch (req.msg) {
                .get_account_range => |*account_range_req| account_range_req.root = pivot_root,
                .get_storage_ranges => |*storage_ranges_req| {
                    storage_ranges_req.root_hash = pivot_root;
                    // healing may have changed the storage roots of the stashed accounts
                    for (storage_ranges_req.account_hashes, req.storage_roots) |account_hash, *root| {
                        const account = try self.eth_db.readAccount(txn, account_hash);
                        root.* = if (account) |acc| acc.storage_hash else types.empty_root_hash;
                    }
                },
                else => {},
            }

            self.sendSnapRequest(req) catch {};
        }
        self.stashed_snap_requests.len = 0;
    }

    fn advanceHeaderDownload(self: *Self) !void {
        const target = self.syncTarget();

        var status = &self.header.?;
        if (status.requested_header_tail != std.math.maxInt(u64) and status.requested_header_head < target.number) {
            // target moved, fill the gap from new head to old head
            requestHeaders(
                self,
                self.popFreeEthRequest() orelse return,
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
                self.popFreeEthRequest() orelse return,
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

    fn handleHeaders(self: *Self, matched_request: *Request(eth.Message), outcome: anyerror!ValidationOutcome) !void {
        const headers_request = matched_request.msg.get_block_headers;

        const hashes, const headers = if (outcome) |result| .{ result.headers.hashes, result.headers.headers } else |e| {
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

    fn hasHeaderRequest(list: *List(Request(eth.Message))) bool {
        var current_node = list.inner.first;
        while (current_node) |node| : (current_node = node.next) {
            const request: *List(Request(eth.Message)).Node = @alignCast(@fieldParentPtr("node", node));
            if (request.elem.msg == .get_block_headers) return true;
        }
        return false;
    }

    fn checkHeaderDownloadComplete(self: *Self) !void {
        const target = self.syncTarget();
        if (self.header.?.requested_header_head < target.number or
            self.header.?.requested_header_tail > target.cutoff_number)
            return;

        if (!self.pending_eth_requests.empty()) return;
        if (hasHeaderRequest(&self.inflight_eth_requests) or hasHeaderRequest(&self.validating_eth_requests)) return;

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
                    self.state_heal = .{
                        .target_pivot = try self.readHeader(new_pivot_height) orelse unreachable,
                        .next_pivot = try self.readHeader(cur_pivot.number + 1) orelse unreachable,
                        .start_number = cur_pivot.number,
                        .started_at = std.Io.Clock.now(.real, self.io),
                    };
                    log.info("state heal: started, pivot {} -> {} ({} blocks)", .{
                        cur_pivot.number,
                        new_pivot_height,
                        new_pivot_height - cur_pivot.number,
                    });
                }
            }

            log.debug("new pivot {}, old {}", .{ new_pivot, cur_pivot });
            self.state.?.pivot = new_pivot;
            if (cur_pivot.number == 0) self.requestAccountRange(
                self.free_snap_requests.pop() orelse unreachable,
                new_pivot.state_root,
                0,
                std.math.maxInt(u256),
            );
        }
    }

    fn advanceStateDownload(self: *Self) !void {
        if (self.state_heal != null) return; // state download is paused

        const state = &self.state.?;

        switch (state.phase) {
            .accounts => {},
            .storage => try self.advanceStorageDownload(),
            .codes => try self.advanceCodesDownload(),
        }

        if (self.state.?.pivot.number > 0 and self.inflight_snap_requests.empty() and
            self.pending_snap_requests.empty() and self.validating_snap_requests.empty() and
            self.stashed_snap_requests.len == 0 and self.snap_flush_queue.empty())
        {
            log.info("{t} download done", .{state.phase});
            switch (state.phase) {
                .accounts => state.phase = .storage,
                .storage => {
                    state.code_hashes.sortUnstable(CodeHashOrder{ .keys = state.code_hashes.keys() });
                    state.phase = .codes;
                },
                .codes => {
                    state.code_hashes.deinit(std.heap.page_allocator);
                    self.state = null;
                    log.info("state download done", .{});
                },
            }
        }
    }

    fn requestAccountRange(self: *Self, req: *Request(snap.Message), state_root: [32]u8, origin: u256, limit: u256) void {
        log.debug("requesting account range origin: {x} limit: {x}", .{ origin, limit });
        var origin_bytes: [32]u8 = undefined;
        var limit_bytes: [32]u8 = undefined;
        std.mem.writeInt(u256, &origin_bytes, origin, .big);
        std.mem.writeInt(u256, &limit_bytes, limit, .big);

        req.msg = .{ .get_account_range = .{
            .root = state_root,
            .origin = origin_bytes,
            .limit = limit_bytes,
        } };
        self.sendSnapRequest(req) catch {};
    }

    fn handleAccounts(self: *Self, request: *Request(snap.Message), outcome: anyerror!ValidationOutcome) !void {
        const get_accounts_range = request.msg.get_account_range;

        var continue_from_account: ?[32]u8 = null;
        if (outcome) |result| {
            const accounts = result.accounts;
            const hashes = accounts.hashes;
            const last = if (hashes.len > 0) hashes[hashes.len - 1] else get_accounts_range.limit;
            log.debug("verified account range {x}-{x}", .{ get_accounts_range.origin, last });
            if (accounts.has_more and std.mem.order(u8, &last, &get_accounts_range.limit) == .lt) {
                var next: [32]u8 = undefined;
                std.mem.writeInt(u256, &next, std.mem.readInt(u256, &last, .big) + 1, .big);
                continue_from_account = next;
            }
            const covered_until = if (accounts.has_more) last else get_accounts_range.limit;
            self.progress.account_keyspace +|= std.mem.readInt(u256, &covered_until, .big) - std.mem.readInt(u256, &get_accounts_range.origin, .big);
            for (accounts.code_hashes) |code_hash|
                try self.state.?.code_hashes.put(std.heap.page_allocator, code_hash, {});
        } else |_| {
            continue_from_account = get_accounts_range.origin;
        }

        const state = &self.state.?;
        const prev_origin = std.mem.readInt(u256, &get_accounts_range.origin, .big);
        const limit = std.mem.readInt(u256, &get_accounts_range.limit, .big);
        if (continue_from_account) |origin_bytes| {
            log.debug("remaining account range {x}-{x}", .{ origin_bytes, get_accounts_range.limit });

            const origin = std.mem.readInt(u256, &origin_bytes, .big);
            if (state.account_fetch_step == 0 and origin != prev_origin) {
                // first response of the initial full range request sizes the chunks
                state.account_fetch_step = origin - prev_origin;
                state.account_fetch_head = origin;
                self.requestAccountChunks(request);
            } else {
                self.requestAccountRange(request, state.pivot.state_root, origin, limit);
            }
        } else if (prev_origin != limit and limit < std.math.maxInt(u256)) {
            self.requestAccountChunks(request);
        } else {
            self.free_snap_requests.push(request);
        }
    }

    fn requestAccountChunks(self: *Self, request: *Request(snap.Message)) void {
        const state = &self.state.?;
        const max = std.math.maxInt(u256);

        var req = request;
        while (state.account_fetch_head < max) {
            const origin = state.account_fetch_head;
            const limit = if (max - origin > state.account_fetch_step +| 1) origin + state.account_fetch_step else max;
            self.requestAccountRange(req, state.pivot.state_root, origin, limit);
            state.account_fetch_head = limit +| 1;
            req = self.popFreeSnapRequest() orelse return;
        }
        self.free_snap_requests.push(req);
    }

    fn persistAccounts(self: *Self, accounts: VerifiedAccounts, response: *const snap.AccountRange) !void {
        const txn_start = std.Io.Timestamp.now(self.io, .awake);
        const txn = try self.eth_db.kv_store.transaction_rw();
        errdefer _ = txn.abort() catch |e| {
            log.err("failed to abort txn {}", .{e});
        };

        const write_op: lmdbx.Database.SetFlag = if (std.meta.eql(accounts.origin, accounts.limit)) .Upsert else .Append;
        const table = self.eth_db.kv_store.table(txn, .accounts);
        for (accounts.hashes, 0..) |hash, index| {
            try table.set(&hash, response.accounts[index].account.value, write_op);
        }
        // a proven single account query that doesn't return the account means it no longer exists
        if (std.meta.eql(accounts.origin, accounts.limit) and (accounts.hashes.len == 0 or !std.meta.eql(accounts.hashes[0], accounts.origin))) {
            try self.eth_db.deleteAccount(txn, accounts.origin);
        }

        try self.commitTxn(txn, "accounts", txn_start);
    }

    fn advanceStorageDownload(self: *Self) !void {
        const state = &self.state.?;

        if (self.free_snap_requests.empty()) return;

        const build_start = std.Io.Timestamp.now(self.io, .awake);
        var scanned: u64 = 0;
        defer if (scanned > 0) {
            self.metrics.batch_build_seconds.observe(secondsSince(self.io, build_start));
            self.metrics.batch_accounts_scanned.incrBy(scanned);
        };

        const txn = try self.eth_db.kv_store.transaction_ro();
        defer txn.abort() catch unreachable;
        const accounts_table = self.eth_db.kv_store.table(txn, .accounts);
        const account_iterator = try accounts_table.cursor();
        defer account_iterator.deinit();

        if (try account_iterator.seekLowerBound(&state.storage_fetch_head) == null)
            return;

        while (true) {
            const storage_request = self.popFreeSnapRequest();
            if (storage_request == null) {
                return;
            }
            errdefer {
                self.free_snap_requests.push(storage_request.?);
            }

            var account_hashes = try self.allocator.alloc([32]u8, batch_storage_code_req_size);
            account_hashes.len = 0;
            errdefer {
                account_hashes.len = batch_storage_code_req_size;
                self.allocator.free(account_hashes);
            }
            var storage_roots = try self.allocator.alloc([32]u8, batch_storage_code_req_size);
            storage_roots.len = 0;
            errdefer {
                storage_roots.len = batch_storage_code_req_size;
                self.allocator.free(storage_roots);
            }

            const batch_start = std.mem.readInt(u256, &state.storage_fetch_head, .big);
            const accounts_exhausted = while (true) {
                scanned += 1;
                const cur = try account_iterator.getCurrentEntry();
                state.storage_fetch_head = cur.key[0..32].*;

                const acc = EthDb.decodeAccount(cur.value) catch unreachable;
                const has_storage = !std.meta.eql(acc.storage_hash, types.empty_root_hash);

                if (has_storage and account_hashes.len == batch_storage_code_req_size)
                    break false;

                if (has_storage) {
                    account_hashes.len += 1;
                    account_hashes[account_hashes.len - 1] = cur.key[0..32].*;
                    storage_roots.len += 1;
                    storage_roots[storage_roots.len - 1] = acc.storage_hash;
                }

                if (try account_iterator.goToNext() == null) break true;
            };

            const batch_end = if (accounts_exhausted) std.math.maxInt(u256) else std.mem.readInt(
                u256,
                &state.storage_fetch_head,
                .big,
            );
            storage_request.?.keyspace = .{ batch_start, batch_end };
            storage_request.?.storage_roots = storage_roots;
            self.requestStorageRanges(storage_request.?, state.pivot.state_root, account_hashes);

            if (accounts_exhausted) {
                std.mem.writeInt(u256, &state.storage_fetch_head, std.mem.readInt(u256, &state.storage_fetch_head, .big) +| 1, .big);
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

    fn handleStorage(self: *Self, req: *Request(snap.Message), outcome: anyerror!ValidationOutcome) !void {
        const result: VerifiedStorage = if (outcome) |verified| verified.storage else |_| .{};
        const request = &req.msg.get_storage_ranges;
        const requested_accounts = request.account_hashes;
        const storage_roots = req.storage_roots;
        const verified = result.keys.len;

        var next = verified;
        var starting_hash: [32]u8 = if (verified > 0) @splat(0) else request.starting_hash;
        if (result.continue_from_slot) |from| {
            const origin = std.mem.readInt(u256, &from, .big);
            const limit = std.mem.readInt(u256, &request.limit_hash, .big);
            if (verified < requested_accounts.len) {
                if (self.free_snap_requests.pop()) |new_req| {
                    try self.requestSlots(new_req, req, verified - 1, origin, std.math.maxInt(u256));
                } else {
                    next = verified - 1;
                    starting_hash = from;
                }
            } else if (origin <= limit) {
                const received_from: [32]u8 = if (verified == 1) request.starting_hash else @splat(0);
                const step = @max(origin - std.mem.readInt(u256, &received_from, .big), min_split_range);
                if (limit - origin > step and !self.free_snap_requests.empty()) {
                    std.mem.writeInt(u256, &request.limit_hash, origin + step, .big);
                    var start = origin + step + 1;
                    while (self.free_snap_requests.pop()) |new_req| : (start += step + 1) {
                        const end = if (self.free_snap_requests.empty() or limit - start <= step) limit else start + step;
                        try self.requestSlots(new_req, req, verified - 1, start, end);
                        if (end == limit) break;
                    }
                }
                next = verified - 1;
                starting_hash = from;
            }
        }

        const remaining = requested_accounts.len - next;
        if (remaining > 0) {
            std.mem.copyForwards([32]u8, requested_accounts[0..remaining], requested_accounts[next..]);
            std.mem.copyForwards([32]u8, storage_roots[0..remaining], storage_roots[next..]);
            request.account_hashes = requested_accounts[0..remaining];
            req.storage_roots = storage_roots[0..remaining];
            request.starting_hash = starting_hash;
            self.sendSnapRequest(req) catch {};
        } else {
            self.allocator.free(@as([][32]u8, requested_accounts.ptr[0..batch_storage_code_req_size]));
            self.allocator.free(@as([][32]u8, storage_roots.ptr[0..batch_storage_code_req_size]));
            self.progress.storage_keyspace +|= req.keyspace[1] - req.keyspace[0];
            self.free_snap_requests.push(req);
        }
    }

    fn persistStorage(self: *Self, storage: VerifiedStorage) !void {
        const txn_start = std.Io.Timestamp.now(self.io, .awake);
        const txn = try self.eth_db.kv_store.transaction_rw();
        errdefer _ = txn.abort() catch |e| {
            log.err("failed to abort txn {}", .{e});
        };
        for (storage.account_hashes, storage.keys, storage.values) |account_hash, keys, values|
            try self.eth_db.appendStorage(txn, account_hash, keys, values, !storage.chunk);
        try self.commitTxn(txn, "storage", txn_start);
    }

    fn requestSlots(self: *Self, new_req: *Request(snap.Message), req: *const Request(snap.Message), account: usize, start: u256, end: u256) !void {
        log.debug("requesting slots of account {x} start: {x} end: {x}", .{ req.msg.get_storage_ranges.account_hashes[account], start, end });
        const hashes = try self.allocator.alloc([32]u8, batch_storage_code_req_size);
        errdefer self.allocator.free(hashes);
        const roots = try self.allocator.alloc([32]u8, batch_storage_code_req_size);
        hashes[0] = req.msg.get_storage_ranges.account_hashes[account];
        roots[0] = req.storage_roots[account];
        new_req.keyspace = .{ 0, 0 };
        new_req.storage_roots = roots[0..1];
        new_req.msg = .{ .get_storage_ranges = .{
            .account_hashes = hashes[0..1],
            .root_hash = req.msg.get_storage_ranges.root_hash,
        } };
        std.mem.writeInt(u256, &new_req.msg.get_storage_ranges.starting_hash, start, .big);
        std.mem.writeInt(u256, &new_req.msg.get_storage_ranges.limit_hash, end, .big);
        self.sendSnapRequest(new_req) catch {};
    }

    fn advanceCodesDownload(self: *Self) !void {
        const state = &self.state.?;
        const code_hashes = state.code_hashes.keys();

        while (state.code_fetch_head < code_hashes.len) {
            const code_request = self.popFreeSnapRequest() orelse return;
            errdefer self.free_snap_requests.push(code_request);

            const batch = try self.allocator.alloc([32]u8, batch_storage_code_req_size);
            const count = @min(code_hashes.len - state.code_fetch_head, batch_storage_code_req_size);
            @memcpy(batch[0..count], code_hashes[state.code_fetch_head..][0..count]);

            const batch_start = if (state.code_fetch_head == 0) 0 else std.mem.readInt(u256, &code_hashes[state.code_fetch_head], .big);
            state.code_fetch_head += count;
            const batch_end = if (state.code_fetch_head == code_hashes.len) std.math.maxInt(u256) else std.mem.readInt(u256, &code_hashes[state.code_fetch_head], .big);
            code_request.keyspace = .{ batch_start, batch_end };
            self.requestCodes(code_request, batch[0..count]);
        }
    }

    fn requestCodes(self: *Self, req: *Request(snap.Message), code_hashes: [][32]u8) void {
        log.debug("requesting codes: {}", .{code_hashes.len});
        req.msg = .{ .get_byte_codes = .{
            .hashes = code_hashes,
        } };
        self.sendSnapRequest(req) catch {};
    }

    fn handleCodes(self: *Self, req: *Request(snap.Message), outcome: anyerror!ValidationOutcome) !void {
        const code_hashes: [][32]u8 = if (outcome) |result| result.codes else |_| &.{};

        const requested_hashes = req.msg.get_byte_codes.hashes;

        var retry_count: usize = 0;
        var next_hash_index: usize = 0;
        for (code_hashes) |code_hash| {
            while (next_hash_index < requested_hashes.len and !std.meta.eql(requested_hashes[next_hash_index], code_hash)) : (next_hash_index += 1) {
                requested_hashes[retry_count] = requested_hashes[next_hash_index];
                retry_count += 1;
            }
            if (next_hash_index == requested_hashes.len) break;
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

    fn persistCodes(self: *Self, hashes: []const [32]u8, codes: []const []const u8) !void {
        const txn_start = std.Io.Timestamp.now(self.io, .awake);
        const txn = try self.eth_db.kv_store.transaction_rw();
        errdefer _ = txn.abort() catch |e| {
            log.err("failed to abort txn {}", .{e});
        };
        const table = self.eth_db.kv_store.table(txn, .codes);
        for (hashes, codes) |hash, code| {
            table.set(&hash, code, .Create) catch |e| {
                if (e != lmdbx.Error.MDBX_KEYEXIST) return e;
            };
        }
        try self.commitTxn(txn, "codes", txn_start);
    }

    fn advanceStateHeal(self: *Self) !void {
        const state_heal = &self.state_heal.?;

        if (state_heal.bal_applied) {
            if (state_heal.next_pivot.number + 1 > state_heal.target_pivot.number) {
                if (self.fetchStaleStorageRoots()) return;
            }
            if (self.inflight_snap_requests.empty() and self.pending_snap_requests.empty() and
                self.validating_snap_requests.empty())
            {
                if (state_heal.next_pivot.number + 1 > state_heal.target_pivot.number) {
                    log.info("state heal: done, healed {} blocks in {}s", .{
                        state_heal.target_pivot.number - state_heal.start_number,
                        state_heal.started_at.durationTo(std.Io.Clock.now(.real, self.io)).toSeconds(),
                    });
                    state_heal.stale_storage_roots.deinit(self.allocator);
                    self.state_heal = null;
                    try self.popSnapRequests();
                    return;
                }

                state_heal.next_pivot = try self.readHeader(state_heal.next_pivot.number + 1) orelse unreachable;
                std.debug.assert(std.meta.eql(state_heal.pivot_hash_buf[0], state_heal.next_pivot.parent_hash));
                state_heal.pivot_hash_buf[0] = state_heal.next_pivot.hash();
                state_heal.bal_requested = false;
                state_heal.bal_applied = false;
            }
        }

        if (state_heal.bal_requested == false) {
            if (!self.validating_snap_requests.empty() or !self.snap_flush_queue.empty()) return;
            self.stashSnapRequests();
            const bal_req = self.free_eth_requests.pop() orelse return;

            state_heal.pivot_hash_buf[0] = state_heal.next_pivot.hash();
            self.requestBals(bal_req, state_heal.pivot_hash_buf[0..1]);
            state_heal.bal_requested = true;
        }
    }

    fn requestBals(self: *Self, req: *Request(eth.Message), hashes: [][32]u8) void {
        req.msg = .{ .get_block_access_list = .{ .hashes = hashes } };
        self.sendEthRequest(req, true);
    }

    fn handleBals(self: *Self, req: *Request(eth.Message), outcome: anyerror!ValidationOutcome) !void {
        if (self.state_heal) |*state_heal| {
            if (outcome) |result| {
                if (std.meta.eql(result.bal.hash, state_heal.next_pivot.block_access_list_hash.?)) {
                    std.debug.assert(!state_heal.bal_applied);
                    try self.applyBal(result.bal.parsed);
                    state_heal.bal_applied = true;
                    self.free_eth_requests.push(req);
                    try self.advanceStateHeal();
                    return;
                }
            } else |_| {}
            self.requestBals(req, state_heal.pivot_hash_buf[0..1]);
        } else unreachable;
    }

    fn applyBal(self: *Self, bal: types.BlockAccessLists) !void {
        const txn_start = std.Io.Timestamp.now(self.io, .awake);
        const txn = try self.eth_db.kv_store.transaction_rw();
        defer self.commitTxn(txn, "bal", txn_start) catch unreachable;
        const codes = self.eth_db.kv_store.table(txn, .codes);

        for (bal) |changes| {
            if (changes.balance_changes.len == 0 and
                changes.code_changes.len == 0 and
                changes.nonce_changes.len == 0 and
                changes.storage_changes.len == 0) continue;

            var addr_buf: [20]u8 = undefined;
            std.mem.writeInt(u160, &addr_buf, changes.addr, .big);
            var addr_hash: [32]u8 = undefined;
            std.crypto.hash.sha3.Keccak256.hash(&addr_buf, &addr_hash, .{});
            if (!self.isAccountFetched(addr_hash)) continue;
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

            if (changes.storage_changes.len > 0 and !self.isStorageFetched(addr_hash, null)) {
                try self.state_heal.?.stale_storage_roots.put(self.allocator, addr_hash, {});
            } else {
                var updated_account = try self.eth_db.readAccount(txn, addr_hash) orelse types.EmptyAccount;
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
    }

    fn isAccountFetched(self: *Self, account_hash: [32]u8) bool {
        std.debug.assert(self.state_heal != null);
        const state = &self.state.?;
        if (state.phase != .accounts) return true;

        var fetched_until: [32]u8 = undefined;
        std.mem.writeInt(u256, &fetched_until, state.account_fetch_head, .big);
        for (self.stashed_snap_requests) |request| {
            if (request.msg != .get_account_range) continue;
            const origin = request.msg.get_account_range.origin;
            if (std.mem.order(u8, &origin, &fetched_until) == .lt) fetched_until = origin;
        }
        return std.mem.order(u8, &account_hash, &fetched_until) == .lt;
    }

    fn isStorageFetched(self: *Self, account_hash: [32]u8, slot_hash: ?[32]u8) bool {
        std.debug.assert(self.state_heal != null);
        const state = &self.state.?;
        if (state.phase == .accounts) return false;
        if (state.phase == .storage and
            std.mem.order(u8, &account_hash, &state.storage_fetch_head) != .lt) return false;

        for (self.stashed_snap_requests) |request| {
            if (request.msg != .get_storage_ranges) continue;
            const storage_request = request.msg.get_storage_ranges;
            for (storage_request.account_hashes, 0..) |requested_account, index| {
                if (!std.meta.eql(requested_account, account_hash)) continue;
                const slot = slot_hash orelse return false;
                if (index > 0) return false;
                if (std.mem.order(u8, &slot, &storage_request.starting_hash) != .lt and
                    std.mem.order(u8, &slot, &storage_request.limit_hash) != .gt) return false;
            }
        }
        return true;
    }

    fn fetchStaleStorageRoots(self: *Self) bool {
        const stale_storage_roots = &self.state_heal.?.stale_storage_roots;
        const idle = self.inflight_snap_requests.empty() and self.pending_snap_requests.empty() and
            self.validating_snap_requests.empty();
        if (idle) {
            if (stale_storage_roots.count() == 0) return false;
            log.info("state heal: fetching {} accounts with stale storage roots", .{stale_storage_roots.count()});
        }

        while (stale_storage_roots.count() > 0) {
            const req = self.free_snap_requests.pop() orelse break;
            const account_hash = stale_storage_roots.pop().?.key;
            const account = std.mem.readInt(u256, &account_hash, .big);
            self.requestAccountRange(req, self.state.?.pivot.state_root, account, account);
        }
        return true;
    }

    fn commitTxn(self: *Self, txn: kv.Transaction, op: []const u8, started_at: std.Io.Timestamp) !void {
        const commit_start = std.Io.Timestamp.now(self.io, .awake);
        try txn.commit();
        self.metrics.db_commit_seconds.observe(.{ .op = op }, secondsSince(self.io, commit_start)) catch {};
        self.metrics.db_txn_seconds.observe(.{ .op = op }, secondsSince(self.io, started_at)) catch {};
    }

    fn observeHandle(self: *Self, msg: []const u8, started_at: std.Io.Timestamp) void {
        self.metrics.handle_seconds.observe(.{ .msg = msg }, secondsSince(self.io, started_at)) catch {};
    }

    pub fn writeMetrics(self: *Self, writer: *std.Io.Writer) !void {
        return prom.write(&self.metrics, writer);
    }

    fn updateMetrics(self: *Self) void {
        const m = &self.metrics;
        const request_counts = [_]struct { []const u8, []const u8, usize }{
            .{ "eth", "inflight", self.inflight_eth_requests.inner.len() },
            .{ "eth", "pending", self.pending_eth_requests.inner.len() },
            .{ "eth", "validating", self.validating_eth_requests.inner.len() },
            .{ "snap", "inflight", self.inflight_snap_requests.inner.len() },
            .{ "snap", "pending", self.pending_snap_requests.inner.len() },
            .{ "snap", "validating", self.validating_snap_requests.inner.len() },
            .{ "snap", "stashed", self.stashed_snap_requests.len },
            .{ "eth", "free", self.free_eth_requests.inner.len() },
            .{ "snap", "free", self.free_snap_requests.inner.len() },
        };
        for (request_counts) |c| m.requests.set(.{ .proto = c[0], .state = c[1] }, c[2]) catch {};

        m.sync_target.set(self.syncTarget().number);
        if (self.bc.head()) |head| m.chain_head.set(head.number) else |_| {}
        m.headers_downloaded.set(self.progress.headers);
        if (self.state) |state| m.pivot.set(state.pivot.number);
        m.state_progress.set(.{ .kind = "accounts" }, keyspacePercent(self.progress.account_keyspace)) catch {};
        m.state_progress.set(.{ .kind = "storage" }, keyspacePercent(self.progress.storage_keyspace)) catch {};
        m.state_progress.set(.{ .kind = "codes" }, keyspacePercent(self.progress.code_keyspace)) catch {};
        if (self.eth_db.kv_store.env.info()) |info| m.db_size_bytes.set(info.geo.current) else |_| {}
        m.heal_blocks_remaining.set(if (self.state_heal) |heal| heal.target_pivot.number -| (heal.next_pivot.number - 1) else 0);
        m.snap_flush_queue_entries.set(self.snap_flush_queue.inner.len());
        m.snap_flush_queue_bytes.set(self.snap_flush_queue_bytes);
        const flush_head = if (self.snap_flush_queue.inner.first) |list_node|
            &@as(*List(QueuedSnapFlush).Node, @alignCast(@fieldParentPtr("node", list_node))).elem
        else
            null;
        m.snap_flush_queue_blocked.set(if (flush_head) |head| @intFromBool(self.hasPrecedingSnapRequest(head)) else 0);
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
            log.info("state download: pivot {}, {t} {d:.2}%, inflight requests {}, healing {}", .{
                state.pivot.number,
                state.phase,
                keyspacePercent(switch (state.phase) {
                    .accounts => self.progress.account_keyspace,
                    .storage => self.progress.storage_keyspace,
                    .codes => self.progress.code_keyspace,
                }),
                self.inflight_snap_requests.inner.len(),
                self.state_heal != null,
            });
        }
        if (self.state_heal) |state_heal| {
            const healed = state_heal.next_pivot.number - 1 - state_heal.start_number;
            const total = state_heal.target_pivot.number - state_heal.start_number;
            const bal_status = if (state_heal.bal_applied) "applied" else if (state_heal.bal_requested) "requested" else "not requested";
            log.info("state heal: block {} ({}/{} healed, {}s elapsed), bal {s}, inflight snap {}, pending snap {}, inflight eth {}", .{
                state_heal.next_pivot.number,
                healed,
                total,
                state_heal.started_at.durationTo(now).toSeconds(),
                bal_status,
                self.inflight_snap_requests.inner.len(),
                self.pending_snap_requests.inner.len(),
                self.inflight_eth_requests.inner.len(),
            });
        }
    }

    fn keyspacePercent(covered: u256) f64 {
        return @as(f64, @floatFromInt(@as(u64, @truncate(covered >> 192)))) / std.math.pow(f64, 2, 64) * 100;
    }
};

fn Request(comptime msg: type) type {
    return struct {
        id: u64,
        peer: rlpx.Server.PeerId,
        msg: msg,
        sent_at: std.Io.Timestamp,
        deadline: std.Io.Timestamp,
        keyspace: [2]u256 = .{ 0, 0 },
        storage_roots: [][32]u8 = &.{},

        fn lessThan(ctx: void, left: @This(), right: @This()) bool {
            return msg.lessThan(ctx, left.msg, right.msg);
        }
    };
}

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

const ValidatedResponse = struct {
    arena: std.heap.ArenaAllocator,
    resp: union(enum) {
        eth: struct { msg: eth.Provider.ParsedMessage, req: *Request(eth.Message) },
        snap: struct { msg: snap.Provider.ParsedMessage, req: *Request(snap.Message) },

        fn msgName(self: *const @This()) []const u8 {
            return switch (self.*) {
                inline else => |resp| @tagName(resp.msg.msg),
            };
        }
    },
    outcome: anyerror!ValidationOutcome = error.NotValidated,

    fn deinit(self: *const ValidatedResponse, allocator: std.mem.Allocator) void {
        switch (self.resp) {
            inline else => |resp| allocator.free(resp.msg.read.payload),
        }
        self.arena.deinit();
    }
};

const ValidationOutcome = union(enum) {
    headers: struct { hashes: [][32]u8, headers: []types.BlockHeader },
    bal: struct { hash: [32]u8, parsed: types.BlockAccessLists },
    accounts: VerifiedAccounts,
    storage: VerifiedStorage,
    codes: [][32]u8,
};

const VerifiedAccounts = struct {
    origin: [32]u8,
    limit: [32]u8,
    hashes: [][32]u8,
    code_hashes: [][32]u8,
    has_more: bool,
};

const CodeHashOrder = struct {
    keys: []const [32]u8,

    pub fn lessThan(self: CodeHashOrder, a: usize, b: usize) bool {
        return std.mem.order(u8, &self.keys[a], &self.keys[b]) == .lt;
    }
};

fn isStorageChunk(request: snap.GetStorageRanges) bool {
    return request.account_hashes.len == 1 and !std.mem.allEqual(u8, &request.starting_hash, 0);
}

const VerifiedStorage = struct {
    chunk: bool = false,
    account_hashes: [][32]u8 = &.{},
    keys: [][][32]u8 = &.{},
    values: [][][]const u8 = &.{},
    continue_from_slot: ?[32]u8 = null,
};

const QueuedSnapFlush = struct {
    arena: std.heap.ArenaAllocator,
    response: snap.Provider.ParsedMessage,
    validation_outcome: ValidationOutcome,

    fn deinit(self: *const QueuedSnapFlush, allocator: std.mem.Allocator) void {
        allocator.free(self.response.read.payload);
        self.arena.deinit();
    }

    fn size(self: *const QueuedSnapFlush) usize {
        return self.arena.queryCapacity() + self.response.read.payload.len;
    }

    fn lessThan(_: void, left: QueuedSnapFlush, right: QueuedSnapFlush) bool {
        const left_tag = std.meta.activeTag(left.validation_outcome);
        const right_tag = std.meta.activeTag(right.validation_outcome);
        if (left_tag != right_tag) return @backingInt(left_tag) < @backingInt(right_tag);
        return switch (std.mem.order(u8, &left.firstKey(), &right.firstKey())) {
            .lt => true,
            .gt => false,
            .eq => left_tag == .storage and std.mem.order(u8, &firstSlot(left.validation_outcome.storage), &firstSlot(right.validation_outcome.storage)) == .lt,
        };
    }

    fn firstSlot(storage: VerifiedStorage) [32]u8 {
        return if (storage.keys.len > 0 and storage.keys[0].len > 0) storage.keys[0][0] else @splat(0);
    }

    fn firstKey(self: *const QueuedSnapFlush) [32]u8 {
        const keys: []const [32]u8 = switch (self.validation_outcome) {
            .accounts => |accounts| return accounts.origin,
            .storage => |storage| storage.account_hashes,
            .codes => |hashes| hashes,
            else => unreachable,
        };
        return if (keys.len > 0) keys[0] else @splat(0);
    }

    fn isPrecededBy(self: *const QueuedSnapFlush, msg: snap.Message, chunks_precede_later_accounts: bool) bool {
        switch (msg) {
            .get_account_range => |request| return self.validation_outcome == .accounts and
                std.mem.order(u8, &request.origin, &self.firstKey()) == .lt,
            .get_storage_ranges => |request| {
                if (self.validation_outcome != .storage or request.account_hashes.len == 0) return false;
                return switch (std.mem.order(u8, &request.account_hashes[0], &self.firstKey())) {
                    .lt => chunks_precede_later_accounts or !isStorageChunk(request),
                    .gt => false,
                    .eq => std.mem.order(u8, &request.starting_hash, &firstSlot(self.validation_outcome.storage)) == .lt,
                };
            },
            else => return false,
        }
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

const Metrics = struct {
    const duration_buckets: []const f64 = &.{ 0.001, 0.005, 0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30 };
    const MsgLabels = struct { msg: []const u8 };
    const RequestLabels = struct { proto: []const u8, state: []const u8 };
    const KindLabels = struct { kind: []const u8 };
    const OpLabels = struct { op: []const u8 };

    loop_busy_seconds: prom.Counter(f64),
    loop_wait_seconds: prom.Counter(f64),
    handle_seconds: prom.HistogramVec(f64, MsgLabels, duration_buckets),
    requests_sent: prom.CounterVec(u64, MsgLabels),
    request_timeouts: prom.CounterVec(u64, MsgLabels),
    response_seconds: prom.HistogramVec(f64, MsgLabels, duration_buckets),
    verify_seconds: prom.HistogramVec(f64, MsgLabels, duration_buckets),
    requests: prom.GaugeVec(u64, RequestLabels),
    sync_target: prom.Gauge(u64),
    chain_head: prom.Gauge(u64),
    headers_downloaded: prom.Gauge(u64),
    pivot: prom.Gauge(u64),
    state_progress: prom.GaugeVec(f64, KindLabels),
    heal_blocks_remaining: prom.Gauge(u64),
    db_txn_seconds: prom.HistogramVec(f64, OpLabels, duration_buckets),
    db_commit_seconds: prom.HistogramVec(f64, OpLabels, duration_buckets),
    db_size_bytes: prom.Gauge(u64),
    batch_build_seconds: prom.Histogram(f64, duration_buckets),
    batch_accounts_scanned: prom.Counter(u64),
    snap_flush_queue_entries: prom.Gauge(u64),
    snap_flush_queue_bytes: prom.Gauge(u64),
    snap_flush_queue_blocked: prom.Gauge(u64),
    snap_flushed_bytes: prom.Counter(u64),

    fn init(allocator: std.mem.Allocator, io: std.Io) !Metrics {
        const opts: prom.RegistryOpts = .{};
        var handle_seconds: @FieldType(Metrics, "handle_seconds") = try .init(allocator, io, "downloader_handle_seconds", .{ .help = "Time the downloader loop spent handling a message or tick" }, opts);
        errdefer handle_seconds.deinit();
        var requests_sent: @FieldType(Metrics, "requests_sent") = try .init(allocator, io, "downloader_requests_sent_total", .{ .help = "Requests sent to peers" }, opts);
        errdefer requests_sent.deinit();
        var request_timeouts: @FieldType(Metrics, "request_timeouts") = try .init(allocator, io, "downloader_request_timeouts_total", .{ .help = "Requests that timed out" }, opts);
        errdefer request_timeouts.deinit();
        var response_seconds: @FieldType(Metrics, "response_seconds") = try .init(allocator, io, "downloader_response_seconds", .{ .help = "Time from sending a request to matching its response" }, opts);
        errdefer response_seconds.deinit();
        var verify_seconds: @FieldType(Metrics, "verify_seconds") = try .init(allocator, io, "downloader_verify_seconds", .{ .help = "Time spent verifying a snap response off the downloader loop" }, opts);
        errdefer verify_seconds.deinit();
        var requests: @FieldType(Metrics, "requests") = try .init(allocator, io, "downloader_requests", .{ .help = "Requests by protocol and state" }, opts);
        errdefer requests.deinit();
        var state_progress: @FieldType(Metrics, "state_progress") = try .init(allocator, io, "downloader_state_progress", .{ .help = "State download progress in percent of the keyspace" }, opts);
        errdefer state_progress.deinit();
        var db_txn_seconds: @FieldType(Metrics, "db_txn_seconds") = try .init(allocator, io, "downloader_db_txn_seconds", .{ .help = "Write transaction duration from begin to commit, by operation" }, opts);
        errdefer db_txn_seconds.deinit();
        const db_commit_seconds: @FieldType(Metrics, "db_commit_seconds") = try .init(allocator, io, "downloader_db_commit_seconds", .{ .help = "Write transaction commit duration, by operation" }, opts);

        return .{
            .loop_busy_seconds = .init("downloader_loop_busy_seconds_total", .{ .help = "Time the downloader loop spent processing" }, opts),
            .loop_wait_seconds = .init("downloader_loop_wait_seconds_total", .{ .help = "Time the downloader loop spent waiting for messages" }, opts),
            .handle_seconds = handle_seconds,
            .requests_sent = requests_sent,
            .request_timeouts = request_timeouts,
            .response_seconds = response_seconds,
            .verify_seconds = verify_seconds,
            .requests = requests,
            .sync_target = .init("downloader_sync_target", .{ .help = "Block number the downloader is syncing towards" }, opts),
            .chain_head = .init("downloader_chain_head", .{ .help = "Last header persisted in the chain" }, opts),
            .headers_downloaded = .init("downloader_headers_downloaded", .{ .help = "Headers downloaded towards the current target" }, opts),
            .pivot = .init("downloader_pivot", .{ .help = "State download pivot block" }, opts),
            .state_progress = state_progress,
            .heal_blocks_remaining = .init("downloader_heal_blocks_remaining", .{ .help = "Blocks left to heal, 0 when not healing" }, opts),
            .db_txn_seconds = db_txn_seconds,
            .db_commit_seconds = db_commit_seconds,
            .db_size_bytes = .init("downloader_db_size_bytes", .{ .help = "Current size of the state database file" }, opts),
            .batch_build_seconds = .init("downloader_batch_build_seconds", .{ .help = "Time spent building storage and code request batches" }, opts),
            .batch_accounts_scanned = .init("downloader_batch_accounts_scanned_total", .{ .help = "Accounts scanned while building storage and code request batches" }, opts),
            .snap_flush_queue_entries = .init("downloader_snap_flush_queue_entries", .{ .help = "Snap responses waiting to be written to the database" }, opts),
            .snap_flush_queue_bytes = .init("downloader_snap_flush_queue_bytes", .{ .help = "Memory held by the snap responses waiting to be written" }, opts),
            .snap_flush_queue_blocked = .init("downloader_snap_flush_queue_blocked", .{ .help = "1 when the first snap response waiting to be written is waiting on a request" }, opts),
            .snap_flushed_bytes = .init("downloader_snap_flushed_bytes_total", .{ .help = "Memory of the snap responses written to the database" }, opts),
        };
    }
};

fn secondsSince(io: std.Io, start: std.Io.Timestamp) f64 {
    const ns = start.durationTo(std.Io.Timestamp.now(io, .awake)).toNanoseconds();
    return @as(f64, @floatFromInt(ns)) / std.time.ns_per_s;
}
