const std = @import("std");
const rlpx = @import("rlpx.zig");
const rlp = @import("rlp");

pub fn Request(comptime T: type) type {
    return struct {
        id: u64,
        query: T,
    };
}

pub fn Response(comptime T: type) type {
    return struct {
        request_id: u64,
        data: T,
    };
}

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

        peers: []std.atomic.Value(Peer),
        next_random_peer: std.atomic.Value(usize),
        queue: std.Io.Queue(rlpx.QueuedRead),
        req_id: std.atomic.Value(u64),
        server: ?*rlpx.Server,
        hello: ?cfg.Message,

        pub fn init(allocator: std.mem.Allocator) !Self {
            const peers = try allocator.alloc(std.atomic.Value(Peer), rlpx.Server.max_peers);
            errdefer allocator.free(peers);
            @memset(peers, .init(std.mem.zeroes(Peer)));
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

            const tag = std.enums.fromInt(std.meta.Tag(cfg.Message), read.id) orelse
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
            self.peers[peer.peer_index].store(.{ .epoch = peer.peer_epoch, .offset = offset }, .release);
            if (self.hello) |hello|
                self.send(peer, hello) catch {}; //todo: log
        }

        pub fn onDisconnected(ctx: *anyopaque, peer: rlpx.Server.PeerId) void {
            var self: *Self = @ptrCast(@alignCast(ctx));
            self.peers[peer.peer_index].store(std.mem.zeroes(Peer), .release);
        }

        pub fn nextRequestId(self: *Self) u64 {
            return self.req_id.fetchAdd(1, .monotonic);
        }

        pub fn send(self: *Self, peer_id: rlpx.Server.PeerId, msg: cfg.Message) !void {
            const peer = self.peers[peer_id.peer_index].load(.acquire);
            if (peer_id.peer_epoch != peer.epoch or peer.offset == 0) return error.StalePeer;

            switch (msg) {
                inline else => |typed_msg, msg_id| {
                    try self.server.?.queueMsg(peer_id, @intFromEnum(msg_id) + peer.offset, typed_msg);
                },
            }
        }

        pub fn broadcast(self: *Self, msg: cfg.Message) void {
            for (self.peers, 0..) |*p, index| {
                const peer = p.load(.acquire);
                if (peer.offset == 0) continue;
                self.send(.{
                    .peer_index = index,
                    .peer_epoch = peer.epoch,
                }, msg) catch continue;
            }
        }

        pub fn sendToRandomPeer(self: *Self, msg: cfg.Message) !rlpx.Server.PeerId {
            const start_index = self.next_random_peer.load(.acquire);
            for ([2][2]usize{
                [2]usize{ start_index, self.peers.len },
                [2]usize{ 0, start_index },
            }) |range| {
                for (range[0]..range[1]) |index| {
                    const peer = self.peers[index].load(.acquire);
                    if (peer.offset == 0) continue;

                    const peer_id: rlpx.Server.PeerId = .{
                        .peer_index = index,
                        .peer_epoch = peer.epoch,
                    };
                    self.send(peer_id, msg) catch continue;
                    self.next_random_peer.store((index + 1) % self.peers.len, .release);
                    return peer_id;
                }
            }

            return error.FailedSending;
        }

        pub fn peerCount(self: *Self) usize {
            var count: usize = 0;
            for (0..self.peers.len) |index| {
                if (self.peers[index].load(.acquire).offset != 0) count += 1;
            }

            return count;
        }
    };
}
