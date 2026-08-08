const std = @import("std");
const enr = @import("enr.zig");
const secp256k1 = @import("zig-eth-secp256k1");
const rlp = @import("rlp");
const snappy = @import("snappy").raw;
const Ecdsa = std.crypto.sign.ecdsa.EcdsaSecp256k1Sha256;
const Sha256 = std.crypto.hash.sha2.Sha256;
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
const Keccak256 = std.crypto.hash.sha3.Keccak256;
const Aes128 = std.crypto.core.aes.Aes128;
const Aes256 = std.crypto.core.aes.Aes256;
const modes = std.crypto.core.modes;

const p2p_version = 5;
const max_frame_size = 1 << 24;
const ecies_overhead = 65 + 16 + 32; // ephemeral pubkey + IV + HMAC-SHA256 tag

const DisconnectReason = enum(u8) {
    requested = 0x00,
    tcp_error = 0x01,
    breach_of_protocol = 0x02,
    useless_peer = 0x03,
    too_many_peers = 0x04,
    already_connected = 0x05,
    incompatible_version = 0x06,
    null_identity = 0x07,
    client_quitting = 0x08,
    unexpected_identity = 0x09,
    self_identity = 0x0a,
    ping_timeout = 0x0b,
    subprotocol = 0x10,
    _,
};

const MessageId = enum(u8) {
    hello = 0,
    disconnect = 1,
    ping = 2,
    pong = 3,
};

const AuthMessage = struct {
    sig: [65]u8,
    pubkey: [64]u8,
    nonce: [32]u8,
    version: u32 = 4,
};

const AuthRespMessage = struct {
    eph_pub: [64]u8,
    nonce: [32]u8,
    version: u32,
};

const HelloMessage = struct {
    version: u64,
    client_id: []const u8,
    caps: []Capability,
    listen_port: u16,
    node_id: [64]u8,
};

const Message = union(MessageId) {
    hello: HelloMessage,
    disconnect: DisconnectReason,
    ping,
    pong,

    fn decode(allocator: std.mem.Allocator, id: u64, payload: []const u8) !Message {
        switch (id) {
            @intFromEnum(MessageId.hello) => {
                var hello: HelloMessage = undefined;
                _ = try rlp.deserialize(HelloMessage, allocator, payload, &hello);
                return .{ .hello = hello };
            },
            @intFromEnum(MessageId.disconnect) => {
                var reason: u8 = 0xff;
                _ = try rlp.deserialize(u8, undefined, payload, &reason);
                return .{ .disconnect = @enumFromInt(reason) };
            },
            @intFromEnum(MessageId.ping) => return .ping,
            @intFromEnum(MessageId.pong) => return .pong,
            else => return error.UnknownMessage,
        }
    }
};

pub const Capability = struct {
    name: []const u8,
    version: u64,

    fn lessThan(_: void, left: Capability, right: Capability) bool {
        const name_order = std.mem.order(u8, left.name, right.name);
        if (name_order == .eq) return left.version < right.version;
        return name_order == .lt;
    }

    fn offeredBy(self: Capability, caps: []const Capability) bool {
        for (caps) |c| {
            if (c.version == self.version and std.mem.eql(u8, c.name, self.name)) return true;
        }
        return false;
    }
};

pub const RegisteredCapability = struct {
    pub const QueuedPayload = struct { peer: *Peer, id: u64, payload: []u8 };

    cap: Capability,
    message_count: usize,
    required: bool,

    ctx: *anyopaque,
    on_connected: *const fn (*anyopaque, *Peer) void,
    on_disconnected: *const fn (*anyopaque, *Peer) void,
    queue: *std.Io.Queue(QueuedPayload),

    fn lessThan(_: void, left: RegisteredCapability, right: RegisteredCapability) bool {
        return Capability.lessThan({}, left.cap, right.cap);
    }
};

pub const Server = struct {
    const Self = @This();
    const PeerSlot = struct {
        status: std.atomic.Value(enum(u8) {
            Empty,
            Occupied,
            Ready,
            Active,
            Exiting,
            Closing,
        }) = .init(.Empty),
        peer: Peer,
    };
    const max_peers = 50;

    allocator: std.mem.Allocator,
    io: std.Io,

    mutex: std.Io.Mutex = .init,

    keypair: Ecdsa.KeyPair,
    hello: HelloMessage,
    secp: secp256k1.Secp256k1,
    tcp_listener: std.Io.net.Server,

    slots: []PeerSlot,
    proto_handlers: []const RegisteredCapability,

    pub fn init(allocator: std.mem.Allocator, io: std.Io, identity: Ecdsa.KeyPair, port: u16, proto_handlers: []RegisteredCapability) !Self {
        const addr: std.Io.net.IpAddress = .{ .ip4 = .unspecified(port) };
        const slots = try allocator.alloc(PeerSlot, max_peers);
        for (slots) |*s| s.status.store(.Empty, .release);
        std.mem.sort(RegisteredCapability, proto_handlers, {}, RegisteredCapability.lessThan);
        var caps = try allocator.alloc(Capability, proto_handlers.len);
        for (0..caps.len) |index| caps[index] = proto_handlers[index].cap;

        return .{
            .allocator = allocator,
            .io = io,
            .slots = slots,
            .keypair = identity,
            .secp = try secp256k1.Secp256k1.init(),
            .tcp_listener = try std.Io.net.IpAddress.listen(&addr, io, .{}),
            .proto_handlers = proto_handlers,
            .hello = .{
                .version = p2p_version,
                .client_id = "zevm/v0.0.0",
                .caps = caps,
                .listen_port = port,
                .node_id = identity.public_key.toUncompressedSec1()[1..65].*,
            },
        };
    }

    pub fn deinit(self: *Self) void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        self.allocator.free(self.slots);
        self.tcp_listener.deinit(self.io);
    }

    fn sharedCaps(self: *const Self, allocator: std.mem.Allocator, peer_caps: []const Capability) ![]usize {
        const registered = self.proto_handlers;

        const shared = try allocator.alloc(usize, registered.len);
        errdefer allocator.free(shared);

        var len: usize = 0;
        var best: ?usize = null;

        for (registered, 0..) |*r, i| {
            if (r.cap.offeredBy(peer_caps)) {
                best = i;
            } else if (r.required) {
                return error.MissingRequiredCapability;
            }

            const run_end = i + 1 == registered.len or
                !std.mem.eql(u8, registered[i + 1].cap.name, r.cap.name);
            if (!run_end) continue;

            const m = best orelse continue;
            best = null;
            shared[len] = m;
            len += 1;
        }

        return allocator.realloc(shared, len);
    }

    fn matchCap(self: *const Self, caps: []const usize, id: u64) ?struct {
        reg: *const RegisteredCapability,
        offset: u64,
    } {
        var offset: u64 = 0x10;
        for (caps) |c| {
            const reg = &self.proto_handlers[c];
            if (id < offset + reg.message_count) return .{ .reg = reg, .offset = offset };
            offset += reg.message_count;
        }
        return null;
    }

    pub fn run(self: *Self) !void {
        var peer_listener = try self.io.concurrent(Self.listenPeers, .{self});
        defer peer_listener.cancel(self.io) catch {};

        while (true) {
            const stream = self.tcp_listener.accept(self.io) catch |e| switch (e) {
                std.Io.Cancelable.Canceled, std.Io.net.Server.AcceptError.SocketNotListening => {
                    break;
                },
                else => continue,
            };

            self.acceptPeer(stream) catch {
                stream.close(self.io);
                continue;
            };
        }
    }

    fn acceptPeer(self: *Self, stream: std.Io.net.Stream) !void {
        const slot = try self.allocateSlot();
        errdefer slot.status.store(.Empty, .release);
        slot.peer = try .init(self.allocator, stream, self);
        slot.status.store(.Ready, .release);
    }

    fn listenPeers(self: *Self) !void {
        const storage = try self.allocator.alloc(std.Io.Operation.Storage, self.slots.len);
        defer self.allocator.free(storage);

        var batch = std.Io.Batch.init(storage);

        while (true) {
            for (self.slots, 0..) |*slot, index| {
                const slot_status = slot.status.cmpxchgStrong(.Ready, .Active, .acq_rel, .acquire);
                if (slot_status == null) {
                    _ = slot.peer.ref();
                    slot.peer.read_iov = .{slot.peer.readBuffer()};
                    batch.addAt(@intCast(index), .{
                        .file_read_streaming = .{ //todo: workaround for https://codeberg.org/ziglang/zig/issues/36190
                            .file = .{
                                .handle = slot.peer.stream.socket.handle,
                                .flags = .{ .nonblocking = false },
                            },
                            .data = &slot.peer.read_iov,
                        },
                    });
                }
            }

            self.io.checkCancel() catch break;
            batch.awaitConcurrent(self.io, .{ .duration = .{
                .clock = .real,
                .raw = .fromSeconds(1),
            } }) catch |e| switch (e) {
                std.Io.Cancelable.Canceled => break,
                else => continue,
            };

            while (batch.next()) |completed| {
                const peer = &self.slots[completed.index].peer;

                const size = completed.result.file_read_streaming catch |e| {
                    if (e == std.Io.Cancelable.Canceled) break;
                    self.dropPeer(peer); // eof or read error
                    continue;
                };

                if (size != 0) {
                    peer.handle(self.io, self.allocator, size) catch |e| {
                        if (e != error.NotEnoughData) {
                            self.dropPeer(peer);
                            continue;
                        }
                    };
                }

                peer.read_iov = .{peer.readBuffer()};
                batch.addAt(@intCast(completed.index), .{
                    .file_read_streaming = .{
                        .file = .{
                            .handle = peer.stream.socket.handle,
                            .flags = .{ .nonblocking = false },
                        },
                        .data = &peer.read_iov,
                    },
                });
            }
        }
    }

    pub fn requestDrop(self: *Self, peer: *Peer) void {
        const slot: *PeerSlot = @alignCast(@fieldParentPtr("peer", peer));
        if (slot.status.cmpxchgStrong(.Active, .Exiting, .acq_rel, .acquire) == null) {
            peer.stream.shutdown(self.io, .recv) catch {};
            if (slot.peer.status == .active) {
                for (slot.peer.status.active.caps) |c| {
                    const handler = &self.proto_handlers[c];
                    handler.on_disconnected(handler.ctx, &slot.peer);
                }
            }
        }
    }

    fn dropPeer(self: *Self, peer: *Peer) void {
        self.requestDrop(peer);
        const slot: *PeerSlot = @alignCast(@fieldParentPtr("peer", peer));
        peer.deref();
        self.clearSlot(slot);
    }

    fn clearSlot(self: *Self, slot: *PeerSlot) void {
        if (slot.status.load(.acquire) != .Exiting) return;
        if (slot.peer.ref_count.load(.acquire) == 0 and slot.status.cmpxchgStrong(.Exiting, .Closing, .acq_rel, .acquire) == null) {
            slot.peer.deinit(self.allocator, self.io);
            slot.peer = undefined;
            slot.status.store(.Empty, .release);
        }
    }

    fn allocateSlot(self: *Self) !*PeerSlot {
        for (0..3) |_| {
            for (self.slots) |*slot| {
                self.clearSlot(slot);

                if (slot.status.cmpxchgStrong(.Empty, .Occupied, .acq_rel, .acquire) == null)
                    return slot;
            }
        }
        return error.TooManyPeers;
    }

    pub fn dial(self: *Self, record: enr.Record) !void {
        const remote_addr = record.tcpAddr();
        if (remote_addr == null) return error.NoTcpEndpoint;

        const slot = try self.allocateSlot();
        errdefer slot.status.store(.Empty, .release);

        var init_nonce: [32]u8 = undefined;
        self.io.random(&init_nonce);

        const remote_pubkey = try record.uncompressedPubkey();
        var secret = try sharedSecret(self.keypair.secret_key.toBytes(), remote_pubkey);
        secret = xor32(secret, init_nonce);

        const eph = Ecdsa.KeyPair.generate(self.io);
        const sig = try self.secp.sign(secret, eph.secret_key.toBytes());

        const auth = AuthMessage{
            .nonce = init_nonce,
            .pubkey = self.keypair.public_key.toUncompressedSec1()[1..65].*,
            .sig = sig,
        };

        var rlp_buf: std.array_list.Managed(u8) = .init(self.allocator);
        defer rlp_buf.deinit();
        try rlp_buf.ensureTotalCapacity(2048);
        try rlp.serialize(AuthMessage, self.allocator, auth, &rlp_buf);

        var padSize: u8 = undefined;
        self.io.random((&padSize)[0..1]);

        try rlp_buf.appendNTimes(0, padSize % 100 + 100);

        const total_len = rlp_buf.items.len + ecies_overhead + 2;
        const encrypted_buf = try self.allocator.alloc(u8, total_len);
        std.mem.writeInt(u16, encrypted_buf[0..2], @intCast(total_len - 2), .big);

        _ = try eciesEncrypt(self.io, encrypted_buf[2..], remote_pubkey, rlp_buf.items, encrypted_buf[0..2]);

        const stream = try remote_addr.?.connect(self.io, .{
            .mode = .stream,
        }); //todo: add timeout when implemented by Io.Threaded
        {
            errdefer stream.close(self.io);
            slot.peer = try .init(self.allocator, stream, self);
        }
        errdefer slot.peer.deinit(self.allocator, self.io);
        slot.peer.record = record;
        slot.peer.status = .{ .auth_sent = .{
            .msg = encrypted_buf,
            .init_nonce = init_nonce,
            .eph_key = eph,
        } };
        try slot.peer.write(self.io, encrypted_buf);

        slot.status.store(.Ready, .release);
    }
};

pub const Peer = struct {
    const HandshakeState = struct {
        msg: []const u8,
        init_nonce: [32]u8,
        eph_key: Ecdsa.KeyPair,
    };
    const Session = struct {
        secrets: Secrets,
        pending_frame: ?usize = null, // header read, awaiting body of this size
    };

    ref_count: std.atomic.Value(usize),
    server: *Server,
    stream: std.Io.net.Stream,

    read_iov: [1][]u8,
    rbuf: []u8,
    rbuf_head: usize,
    rbuf_tail: usize,

    status: union(enum) {
        accepted: void,
        auth_sent: HandshakeState,
        auth_resp_length_read: struct {
            len: u16,
            handshake: HandshakeState,
        },
        hello: Session,
        active: struct {
            caps: []usize,
            session: Session,
        },
    },

    record: ?enr.Record,

    fn init(allocator: std.mem.Allocator, stream: std.Io.net.Stream, server: *Server) !Peer {
        return .{
            .server = server,
            .stream = stream,
            .rbuf = try allocator.alloc(u8, max_frame_size),
            .rbuf_head = 0,
            .rbuf_tail = 0,
            .read_iov = .{&.{}},
            .status = .{ .accepted = {} },
            .record = null,
            .ref_count = .init(0),
        };
    }

    fn deinit(self: *Peer, allocator: std.mem.Allocator, io: std.Io) void {
        switch (self.status) {
            .auth_sent => |s| allocator.free(s.msg),
            .auth_resp_length_read => |s| allocator.free(s.handshake.msg),
            .active => |s| allocator.free(s.caps),
            else => {},
        }
        self.stream.close(io);
        allocator.free(self.rbuf);
    }

    pub fn ref(self: *Peer) *Peer {
        _ = self.ref_count.fetchAdd(1, .seq_cst);
        return self;
    }

    pub fn deref(self: *Peer) void {
        _ = self.ref_count.fetchSub(1, .seq_cst);
    }

    fn write(self: *Peer, io: std.Io, buf: []const u8) !void {
        var stream_writer = self.stream.writer(io, &.{});
        var writer = &stream_writer.interface;
        try writer.writeAll(buf);
        try writer.flush();
    }

    fn read(self: *Peer, n: usize) ![]u8 {
        const space_left = self.rbuf.len - self.rbuf_tail;
        const buffer_len = self.rbuf_tail - self.rbuf_head;

        if (buffer_len + space_left < n) {
            // remaining of the rbuf doesn't have enough space to store the requested amount
            @memmove(self.rbuf[0..buffer_len], self.rbuf[self.rbuf_head..self.rbuf_tail]);
            self.rbuf_head = 0;
            self.rbuf_tail = buffer_len;
        }

        if (buffer_len < n) return error.NotEnoughData;

        const buf = self.rbuf[self.rbuf_head .. self.rbuf_head + n];
        self.rbuf_head += n;

        if (self.rbuf_head == self.rbuf_tail) {
            self.rbuf_head = 0;
            self.rbuf_tail = 0;
        }
        return buf;
    }

    fn readBuffer(self: *Peer) []u8 {
        return self.rbuf[self.rbuf_tail..];
    }

    fn handle(self: *Peer, io: std.Io, allocator: std.mem.Allocator, new_bytes_buffered: usize) !void {
        self.rbuf_tail += new_bytes_buffered;

        while (true) {
            switch (self.status) {
                .accepted => return error.NotImplemented, //todo: inbound handshake (read auth, send ack)
                .auth_sent => |state| {
                    const prefix = try self.read(2);
                    const len = std.mem.readInt(u16, prefix[0..2], .big);
                    if (len > 2048) {
                        return error.AuthRespMessageTooBig;
                    }
                    self.status = .{ .auth_resp_length_read = .{ .len = len, .handshake = state } };
                },
                .auth_resp_length_read => |state| {
                    const blob = try self.read(state.len);

                    var s2: [2]u8 = undefined;
                    std.mem.writeInt(u16, &s2, state.len, .big);

                    var plain_buf: [2048]u8 = undefined;
                    const plain = try eciesDecrypt(self.server.keypair.secret_key.toBytes(), &plain_buf, blob, &s2);

                    var resp: AuthRespMessage = undefined;
                    _ = try rlp.deserialize(@TypeOf(resp), undefined, plain, &resp);

                    const ecdhe = try sharedSecret(state.handshake.eph_key.secret_key.toBytes(), resp.eph_pub);
                    const sec = deriveSecrets(
                        ecdhe,
                        state.handshake.init_nonce,
                        resp.nonce,
                        state.handshake.msg,
                        &s2,
                        blob,
                    );

                    var session: Session = .{ .secrets = sec };
                    try self.sendMsg(io, allocator, &session.secrets, @intFromEnum(MessageId.hello), self.server.hello);
                    allocator.free(state.handshake.msg);
                    self.status = .{ .hello = session };
                },
                .hello => |*session| {
                    const frame = try self.readFrame(session) orelse continue;
                    switch (try Message.decode(allocator, frame.id, frame.payload)) {
                        .hello => |hello| {
                            defer allocator.free(hello.caps);
                            if (hello.version < p2p_version) return error.IncompatibleVersion;
                            const caps = try self.server.sharedCaps(allocator, hello.caps);
                            self.status = .{ .active = .{ .session = session.*, .caps = caps } };
                            for (caps) |c| {
                                const handler = &self.server.proto_handlers[c];
                                handler.on_connected(handler.ctx, self);
                            }
                        },
                        .disconnect => return error.Disconnected,
                        else => return error.UnexpectedBeforeHello,
                    }
                },
                .active => |*state| {
                    const f = try self.readFrame(&state.session) orelse continue;

                    const n = try snappy.uncompressedLength(f.payload);
                    if (n > max_frame_size) return error.FrameTooLarge;
                    const payload = try allocator.alloc(u8, n);
                    errdefer allocator.free(payload);
                    _ = try snappy.uncompress(f.payload, payload);

                    if (f.id < 0x10) {
                        switch (try Message.decode(allocator, f.id, payload)) {
                            .disconnect => return error.Disconnected,
                            .ping => try self.sendMsg(io, allocator, &state.session.secrets, @intFromEnum(MessageId.pong), struct {}{}),
                            .pong => {},
                            else => {},
                        }
                        allocator.free(payload);
                    } else {
                        const matched = self.server.matchCap(state.caps, f.id) orelse return error.UnknownMessage;
                        const self_ref = self.ref();
                        const queued = matched.reg.queue.put(io, &.{.{
                            .peer = self_ref,
                            .id = f.id - matched.offset,
                            .payload = payload,
                        }}, 0) catch 0;
                        if (queued == 0) {
                            self_ref.deref();
                            allocator.free(payload);
                        }
                    }
                },
            }
        }
    }

    fn readFrame(self: *Peer, s: *Session) !?struct { id: u64, payload: []u8 } {
        if (s.pending_frame == null) {
            const hdr = try self.read(32);
            if (!std.meta.eql(s.secrets.ingressHeaderMac(hdr[0..16].*), hdr[16..32].*))
                return error.BadHeaderMac;
            var plain: [16]u8 = undefined;
            s.secrets.ingressDecrypt(&plain, hdr[0..16]);
            const size = std.mem.readInt(u24, plain[0..3], .big);
            if (std.mem.alignForward(usize, size, 16) + 16 > self.rbuf.len) return error.FrameTooLarge;
            s.pending_frame = size;
            return null;
        }

        const size = s.pending_frame.?;
        const padded = std.mem.alignForward(usize, size, 16);
        const body = try self.read(padded + 16);
        if (!std.meta.eql(s.secrets.ingressFrameMac(body[0..padded]), body[padded..][0..16].*))
            return error.BadFrameMac;
        s.secrets.ingressDecrypt(body[0..padded], body[0..padded]); // in place
        s.pending_frame = null;

        const message = body[0..size];
        var id: u64 = undefined;
        const off = try rlp.deserialize(u64, undefined, message, &id);
        return .{ .id = id, .payload = message[off..] };
    }

    pub fn sessionSecrets(self: *Peer) !*Secrets {
        switch (self.status) {
            .hello => |*session| return &session.secrets,
            .active => |*state| return &state.session.secrets,
            else => return error.NoActiveSession,
        }
    }

    pub fn sendMsg(self: *Peer, io: std.Io, allocator: std.mem.Allocator, sec: *Secrets, id: u64, msg: anytype) !void {
        var payload: std.array_list.Managed(u8) = .init(allocator);
        defer payload.deinit();
        try payload.ensureTotalCapacity(max_frame_size);
        try rlp.serialize(u64, allocator, id, &payload);

        if (self.status == .active) {
            var body: std.array_list.Managed(u8) = .init(allocator);
            defer body.deinit();
            try body.ensureTotalCapacity(max_frame_size);
            try rlp.serialize(@TypeOf(msg), allocator, msg, &body);

            const id_len = payload.items.len;
            try payload.resize(id_len + snappy.maxCompressedLength(body.items.len));
            const n = try snappy.compress(body.items, payload.items[id_len..]);
            payload.shrinkRetainingCapacity(id_len + n);
        } else {
            try rlp.serialize(@TypeOf(msg), allocator, msg, &payload);
        }

        try self.writeFrame(io, allocator, sec, payload.items);
    }

    fn writeFrame(self: *Peer, io: std.Io, allocator: std.mem.Allocator, sec: *Secrets, payload: []const u8) !void {
        const data_len = payload.len;
        const padded = std.mem.alignForward(usize, data_len, 16);

        var buf = try allocator.alloc(u8, 32 + padded + 16); //todo: get rid of this allocation and copy below
        defer allocator.free(buf);

        var header: [16]u8 = @splat(0);
        std.mem.writeInt(u24, header[0..3], @intCast(data_len), .big);
        header[3] = 0xc2;
        header[4] = 0x80;
        header[5] = 0x80;
        sec.egressEncrypt(buf[0..16], &header);
        buf[16..32].* = sec.egressHeaderMac(buf[0..16].*);

        @memcpy(buf[32..][0..payload.len], payload);
        @memset(buf[32 + data_len ..][0 .. padded - data_len], 0);
        sec.egressEncrypt(buf[32..][0..padded], buf[32..][0..padded]); // in place
        buf[32 + padded ..][0..16].* = sec.egressFrameMac(buf[32..][0..padded]);

        try self.write(io, buf[0 .. 32 + padded + 16]);
    }

    fn deriveSecrets(
        ecdhe: [32]u8,
        init_nonce: [32]u8,
        remote_nonce: [32]u8,
        sent_auth: []const u8,
        recv_ack_prefix: []const u8,
        recv_ack_body: []const u8,
    ) Secrets {
        const nonce_hash = keccak2(&remote_nonce, &init_nonce);
        const shared = keccak2(&ecdhe, &nonce_hash);
        const aes = keccak2(&ecdhe, &shared);
        const mac = keccak2(&ecdhe, &aes);

        var egress_mac = Keccak256.init(.{});
        egress_mac.update(&xor32(mac, remote_nonce));
        egress_mac.update(sent_auth);

        var ingress_mac = Keccak256.init(.{});
        ingress_mac.update(&xor32(mac, init_nonce));
        ingress_mac.update(recv_ack_prefix);
        ingress_mac.update(recv_ack_body);

        return .{ .aes = aes, .mac = mac, .egress_mac = egress_mac, .ingress_mac = ingress_mac };
    }
};

const Secrets = struct {
    aes: [32]u8,
    mac: [32]u8,
    egress_mac: Keccak256,
    ingress_mac: Keccak256,
    egress_ctr: [16]u8 = @splat(0),
    ingress_ctr: [16]u8 = @splat(0),

    fn ctrXor(self: *Secrets, ctr: *[16]u8, dst: []u8, src: []const u8) void {
        const ctx = Aes256.initEnc(self.aes);
        modes.ctr(@TypeOf(ctx), ctx, dst, src, ctr.*, .big);
        var v = std.mem.readInt(u128, ctr, .big);
        v +%= src.len / 16; // frames are 16-padded, so this is exact
        std.mem.writeInt(u128, ctr, v, .big);
    }

    fn peek16(h: Keccak256) [16]u8 {
        var tmp = h;
        var out: [32]u8 = undefined;
        tmp.final(&out);
        return out[0..16].*;
    }

    fn macCompute(self: *Secrets, h: *Keccak256, sum1: [16]u8, seed: [16]u8) [16]u8 {
        const ctx = Aes256.initEnc(self.mac);
        var buf: [16]u8 = undefined;
        ctx.encrypt(&buf, &sum1);
        for (0..16) |i| buf[i] ^= seed[i];
        h.update(&buf);
        return peek16(h.*);
    }

    fn ingressDecrypt(self: *Secrets, dst: []u8, src: []const u8) void {
        self.ctrXor(&self.ingress_ctr, dst, src);
    }
    fn ingressHeaderMac(self: *Secrets, header_ct: [16]u8) [16]u8 {
        return self.macCompute(&self.ingress_mac, peek16(self.ingress_mac), header_ct);
    }
    fn ingressFrameMac(self: *Secrets, frame_ct: []const u8) [16]u8 {
        self.ingress_mac.update(frame_ct);
        const seed = peek16(self.ingress_mac);
        return self.macCompute(&self.ingress_mac, seed, seed);
    }

    fn egressEncrypt(self: *Secrets, dst: []u8, src: []const u8) void {
        self.ctrXor(&self.egress_ctr, dst, src);
    }
    fn egressHeaderMac(self: *Secrets, header_ct: [16]u8) [16]u8 {
        return self.macCompute(&self.egress_mac, peek16(self.egress_mac), header_ct);
    }
    fn egressFrameMac(self: *Secrets, frame_ct: []const u8) [16]u8 {
        self.egress_mac.update(frame_ct);
        const seed = peek16(self.egress_mac);
        return self.macCompute(&self.egress_mac, seed, seed);
    }
};

fn keccak2(a: []const u8, b: []const u8) [32]u8 {
    var h = Keccak256.init(.{});
    h.update(a);
    h.update(b);
    var out: [32]u8 = undefined;
    h.final(&out);
    return out;
}

fn xor32(a: [32]u8, b: [32]u8) [32]u8 {
    var out: [32]u8 = undefined;
    for (0..32) |i| out[i] = a[i] ^ b[i];
    return out;
}

fn sharedSecret(prv: [32]u8, remote_pubkey: [64]u8) ![32]u8 {
    var sec1: [65]u8 = undefined;
    sec1[0] = 4;
    @memcpy(sec1[1..], &remote_pubkey);
    const shared = try (try std.crypto.ecc.Secp256k1.fromSec1(&sec1)).mul(prv, .big); // prv · remote
    return shared.toUncompressedSec1()[1..33].*;
}

fn concatKDF(z: []const u8, s1: []const u8, out: []u8) void {
    var counter: u32 = 1;
    var written: usize = 0;
    while (written < out.len) : (counter += 1) {
        var h = Sha256.init(.{});
        var cbuf: [4]u8 = undefined;
        std.mem.writeInt(u32, &cbuf, counter, .big);
        h.update(&cbuf);
        h.update(z);
        h.update(s1);
        var digest: [32]u8 = undefined;
        h.final(&digest);
        const n = @min(digest.len, out.len - written);
        @memcpy(out[written..][0..n], digest[0..n]);
        written += n;
    }
}

fn eciesEncrypt(io: std.Io, out: []u8, remote_pub: [64]u8, m: []const u8, s2: []const u8) ![]u8 {
    if (out.len < m.len + ecies_overhead) return error.NoSpaceLeft;

    const eph = Ecdsa.KeyPair.generate(io);
    const z = try sharedSecret(eph.secret_key.toBytes(), remote_pub);

    var k: [32]u8 = undefined;
    concatKDF(&z, "", &k);
    var mac_key: [32]u8 = undefined;
    Sha256.hash(k[16..32], &mac_key, .{});

    var iv: [16]u8 = undefined;
    io.random(&iv);

    @memcpy(out[0..65], &eph.public_key.toUncompressedSec1());
    @memcpy(out[65..81], &iv);
    const ct = out[81..][0..m.len];
    const ctx = Aes128.initEnc(k[0..16].*);
    modes.ctr(@TypeOf(ctx), ctx, ct, m, iv, .big);

    var mac = HmacSha256.init(&mac_key);
    mac.update(out[65 .. 81 + m.len]);
    mac.update(s2);
    mac.final(out[81 + m.len ..][0..32]);
    return out[0 .. 81 + m.len + 32];
}

fn eciesDecrypt(priv: [32]u8, out: []u8, c: []const u8, s2: []const u8) ![]u8 {
    if (c.len < ecies_overhead or c[0] != 0x04) return error.InvalidMessage;
    const eph_pub = c[1..65].*;
    const iv = c[65..81].*;
    const body = c[81 .. c.len - 32];
    const tag = c[c.len - 32 ..][0..32].*;
    if (out.len < body.len) return error.NoSpaceLeft;

    const z = try sharedSecret(priv, eph_pub);
    var k: [32]u8 = undefined;
    concatKDF(&z, "", &k);
    var mac_key: [32]u8 = undefined;
    Sha256.hash(k[16..32], &mac_key, .{});

    var mac: [32]u8 = undefined;
    var h = HmacSha256.init(&mac_key);
    h.update(c[65 .. c.len - 32]);
    h.update(s2);
    h.final(&mac);
    if (!std.meta.eql(mac, tag)) return error.InvalidMac;

    const ctx = Aes128.initEnc(k[0..16].*);
    modes.ctr(@TypeOf(ctx), ctx, out[0..body.len], body, iv, .big);
    return out[0..body.len];
}

test "ecies encrypt/decrypt round-trip" {
    var threaded: std.Io.Threaded = .init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const remote = try Ecdsa.KeyPair.generateDeterministic([_]u8{7} ** 32);
    const remote_pub = remote.public_key.toUncompressedSec1()[1..65].*;
    const prefix = [_]u8{ 0x00, 0x8f };
    const m = "super secret message";

    var out: [512]u8 = undefined;
    const enc = try eciesEncrypt(io, &out, remote_pub, m, &prefix);
    try std.testing.expectEqual(m.len + ecies_overhead, enc.len);
    try std.testing.expectEqual(@as(u8, 0x04), enc[0]);

    var pt: [512]u8 = undefined;
    const dec = try eciesDecrypt(remote.secret_key.toBytes(), &pt, enc, &prefix);
    try std.testing.expectEqualSlices(u8, m, dec);
}

test "ecies rejects a tampered ciphertext" {
    var threaded: std.Io.Threaded = .init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const remote = try Ecdsa.KeyPair.generateDeterministic([_]u8{9} ** 32);
    const remote_pub = remote.public_key.toUncompressedSec1()[1..65].*;
    const prefix = [_]u8{ 0x00, 0x40 };

    var out: [256]u8 = undefined;
    const enc = try eciesEncrypt(io, &out, remote_pub, "hello world", &prefix);
    enc[90] ^= 0x01; // flip a ciphertext byte

    var pt: [256]u8 = undefined;
    try std.testing.expectError(error.InvalidMac, eciesDecrypt(remote.secret_key.toBytes(), &pt, enc, &prefix));
}

test "ecies authenticates the prefix (s2)" {
    var threaded: std.Io.Threaded = .init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const remote = try Ecdsa.KeyPair.generateDeterministic([_]u8{3} ** 32);
    const remote_pub = remote.public_key.toUncompressedSec1()[1..65].*;

    var out: [256]u8 = undefined;
    const enc = try eciesEncrypt(io, &out, remote_pub, "payload", &[_]u8{ 0x00, 0x33 });

    // a different prefix must fail the MAC
    var pt: [256]u8 = undefined;
    try std.testing.expectError(error.InvalidMac, eciesDecrypt(remote.secret_key.toBytes(), &pt, enc, &[_]u8{ 0x00, 0x34 }));
}
