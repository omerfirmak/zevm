const std = @import("std");
const rlpx = @import("rlpx.zig");
const rlp = @import("rlp");

const log = std.log.scoped(.proto);

pub const Config = struct {
    name: []const u8,
    version: u64,
    required: bool,
    message_count: usize,
    Message: type,
};

pub fn Provider(comptime cfg: Config) type {
    return struct {
        const Self = @This();
        const Peer = packed struct(u128) {
            epoch: usize,
            offset: usize,
        };
        pub const MessageIds = std.meta.Tag(cfg.Message);
        const default_rtt: std.Io.Duration = .fromSeconds(5);
        const min_timeout: std.Io.Duration = .fromSeconds(3);
        const max_rtt: std.Io.Duration = .fromSeconds(30);
        const PeerSlot = struct {
            info: std.atomic.Value(Peer),
            rtt: std.enums.EnumArray(MessageIds, std.Io.Duration) = .initFill(default_rtt),
        };

        peers: []PeerSlot,
        next_random_peer: std.atomic.Value(usize),
        queue: std.Io.Queue(rlpx.QueuedRead),
        req_id: std.atomic.Value(u64),
        server: ?*rlpx.Server,
        hello: ?cfg.Message,

        pub fn init(allocator: std.mem.Allocator) !Self {
            const peers = try allocator.alloc(PeerSlot, rlpx.Server.max_peers);
            errdefer allocator.free(peers);
            @memset(peers, .{ .info = .init(std.mem.zeroes(Peer)) });
            return .{
                .queue = .init(try allocator.alloc(rlpx.QueuedRead, 1024)),
                .peers = peers,
                .req_id = .init(0),
                .server = null,
                .next_random_peer = .init(0),
                .hello = null,
            };
        }

        pub fn register(self: *Self) rlpx.RegisteredCapability {
            return .{
                .cap = .{
                    .name = cfg.name,
                    .version = cfg.version,
                },
                .message_count = cfg.message_count,
                .required = cfg.required,
                .ctx = @ptrCast(self),
                .onConnected = onConnected,
                .onDisconnected = onDisconnected,
                .queue = &self.queue,
            };
        }

        pub fn next(self: *Self, io: std.Io, allocator: std.mem.Allocator, frame_allocator: std.mem.Allocator) !struct {
            msg: cfg.Message,
            read: rlpx.QueuedRead,
        } {
            const read = try self.queue.getOne(io);
            errdefer frame_allocator.free(read.payload);

            const tag = std.enums.fromInt(MessageIds, read.id) orelse
                return error.InvalidMessageId;
            switch (tag) {
                inline else => |t| {
                    const tag_name = @tagName(t);
                    const FieldType = @FieldType(cfg.Message, tag_name);
                    var field: FieldType = undefined;
                    _ = try rlp.deserialize(FieldType, allocator, read.payload, &field);
                    return .{
                        .msg = @unionInit(cfg.Message, tag_name, field),
                        .read = read,
                    };
                },
            }
        }

        pub fn onConnected(ctx: *anyopaque, peer: rlpx.Server.PeerId, offset: usize) void {
            var self: *Self = @ptrCast(@alignCast(ctx));
            self.peers[peer.peer_index].info.store(.{ .epoch = peer.peer_epoch, .offset = offset }, .release);
            if (self.hello) |hello|
                self.send(peer, hello) catch {}; //todo: log
        }

        pub fn onDisconnected(ctx: *anyopaque, peer: rlpx.Server.PeerId) void {
            var self: *Self = @ptrCast(@alignCast(ctx));
            self.peers[peer.peer_index].info.store(std.mem.zeroes(Peer), .release);
        }

        pub fn disconnect(self: *Self, peer_id: rlpx.Server.PeerId, reason: anyerror) void {
            const info = &self.peers[peer_id.peer_index].info;
            const peer = info.load(.acquire);
            if (peer.offset == 0 or peer.epoch != peer_id.peer_epoch) return;
            if (info.cmpxchgStrong(peer, std.mem.zeroes(Peer), .acq_rel, .acquire) != null) return;
            self.server.?.requestDisconnect(peer_id, reason);
        }

        pub fn nextRequestId(self: *Self) u64 {
            return self.req_id.fetchAdd(1, .monotonic);
        }

        pub fn send(self: *Self, peer_id: rlpx.Server.PeerId, msg: cfg.Message) !void {
            const peer = self.peers[peer_id.peer_index].info.load(.acquire);
            if (peer_id.peer_epoch != peer.epoch or peer.offset == 0) return error.StalePeer;

            switch (msg) {
                inline else => |typed_msg, msg_id| {
                    try self.server.?.queueMsg(peer_id, @backingInt(msg_id) + peer.offset, typed_msg);
                },
            }
        }

        pub fn broadcast(self: *Self, msg: cfg.Message) void {
            for (self.peers, 0..) |*p, index| {
                const peer = p.info.load(.acquire);
                if (peer.offset == 0) continue;
                self.send(.{
                    .peer_index = index,
                    .peer_epoch = peer.epoch,
                }, msg) catch continue;
            }
        }

        pub fn pickRandomPeer(self: *Self, filter: anytype) !rlpx.Server.PeerId {
            const start_index = self.next_random_peer.load(.acquire);
            for ([2][2]usize{
                [2]usize{ start_index, self.peers.len },
                [2]usize{ 0, start_index },
            }) |range| {
                for (range[0]..range[1]) |index| {
                    const peer = self.peers[index].info.load(.acquire);
                    if (peer.offset == 0) continue;

                    const peer_id: rlpx.Server.PeerId = .{
                        .peer_index = index,
                        .peer_epoch = peer.epoch,
                    };
                    if (@TypeOf(filter) != void and !filter.validPeer(peer_id)) continue;
                    self.next_random_peer.store((index + 1) % self.peers.len, .release);
                    return peer_id;
                }
            }
            return error.NoCandidatePeer;
        }

        pub fn sendToRandomPeer(self: *Self, msg: cfg.Message, filter: anytype) !rlpx.Server.PeerId {
            const peer_id = try self.pickRandomPeer(filter);
            try self.send(peer_id, msg);
            return peer_id;
        }

        pub fn peerCount(self: *Self) usize {
            var count: usize = 0;
            for (0..self.peers.len) |index| {
                if (self.peers[index].info.load(.acquire).offset != 0) count += 1;
            }

            return count;
        }

        pub fn timeoutFor(self: *Self, peer_id: rlpx.Server.PeerId, id: MessageIds) !std.Io.Duration {
            const peer = self.peers[peer_id.peer_index].info.load(.acquire);
            if (peer_id.peer_epoch != peer.epoch or peer.offset == 0) {
                self.peers[peer_id.peer_index].rtt.set(id, default_rtt);
                return error.StalePeer;
            }
            const rtt = self.peers[peer_id.peer_index].rtt.get(id);
            return .{ .nanoseconds = @max(min_timeout.nanoseconds, 3 * rtt.nanoseconds) };
        }

        pub fn observeDelay(self: *Self, peer_id: rlpx.Server.PeerId, id: MessageIds, delay: std.Io.Duration) void {
            if (peer_id.peer_index >= self.peers.len) return;
            _ = self.timeoutFor(peer_id, id) catch return;
            const rtt = self.peers[peer_id.peer_index].rtt.getPtr(id);
            rtt.nanoseconds = @divTrunc(8 * rtt.nanoseconds + 2 * delay.nanoseconds, 10);
            if (rtt.nanoseconds > max_rtt.nanoseconds) {
                log.warn("dropping {s} peer {} for slow {t} responses (rtt {}ms)", .{
                    cfg.name,
                    peer_id,
                    id,
                    rtt.toMilliseconds(),
                });
                rtt.* = default_rtt;
                self.disconnect(peer_id, error.SlowPeer);
            }
        }
    };
}
