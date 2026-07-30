const std = @import("std");
const rlp = @import("rlp");
const Enode = @import("enode.zig").Enode;
const enr = @import("enr.zig");
const Secp256k1 = std.crypto.ecc.Secp256k1;
const Ecdsa = std.crypto.sign.ecdsa.EcdsaSecp256k1Sha256;
const HkdfSha256 = std.crypto.kdf.hkdf.HkdfSha256;
const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;
const Aes128 = std.crypto.core.aes.Aes128;

const Flags = enum(u8) { Message = 0, WhoAreYou = 1, Handshake = 2 };
const Messages = enum(u8) { Ping = 1, Pong = 2, FindNode = 3, Nodes = 4 };

// message-data layouts (RLP lists following the 1-byte message type).
const Ping = struct { request_id: []const u8, enr_seq: u64 };
const Pong = struct { request_id: []const u8, enr_seq: u64, ip: []const u8, port: u16 };
const FindNode = struct { request_id: []const u8, distances: []const u16 };
const Nodes = struct { request_id: []const u8, total: u64, records: []rlp.RawValue };

const StaticHeader = struct {
    protocol_id: [6]u8, // "discv5"
    version: [2]u8, // 0x0001
    flag: u8,
    nonce: [12]u8,
    authdata_size: [2]u8,
};

const max_sessions = 4096;
const max_initiated = 1024;

pub const Server = struct {
    const Self = @This();
    const Handshake = struct { pubkey: [64]u8, record: ?enr.Record };

    allocator: std.mem.Allocator,
    io: std.Io,

    keypair: Ecdsa.KeyPair,
    id: [32]u8,

    rx_buf: [1280]u8 = undefined,
    tx_buf: [1280]u8 = undefined,
    socket: std.Io.net.Socket,

    record_buf: [300]u8 = undefined,
    record_len: usize = 0,
    nonce: u96 = 0,

    initiated: std.AutoHashMapUnmanaged([12]u8, Handshake) = .empty,
    sessions: Sessions = .{},

    pub fn init(allocator: std.mem.Allocator, io: std.Io, identity: Ecdsa.KeyPair, port: u16) !Self {
        var s = Server{
            .allocator = allocator,
            .io = io,
            .keypair = identity,
            .id = nodeId(identity.public_key.toUncompressedSec1()[1..65].*),
            .socket = try std.Io.net.IpAddress.bind(&.{
                .ip4 = std.Io.net.Ip4Address.unspecified(port),
            }, io, .{ .mode = .dgram }),
        };
        s.record_len = (try enr.encode(&s.record_buf, identity.secret_key.toBytes(), 1, null, null, null)).len;
        return s;
    }

    pub fn deinit(self: *Self) void {
        self.initiated.deinit(self.allocator);
        self.sessions.deinit(self.allocator);
    }

    pub fn run(self: *Self, bootnodes: []const Enode) !void {
        for (bootnodes) |enode| try self.initiateSession(nodeId(enode.pubkey), enode.pubkey, enode.addr, null);
        while (true) {
            //todo: walk the network periodically and refresh sessions
            const msg = self.socket.receive(self.io, &self.rx_buf) catch |e| {
                if (e == std.Io.Cancelable.Canceled) break;
                continue;
            };
            if (msg.flags.trunc or msg.flags.ctrunc or msg.flags.errqueue) continue;

            const res = self.handlePacket(msg.data, msg.from) catch |e| {
                if (e == std.Io.Cancelable.Canceled) break;
                continue;
            };
            if (res) |packet| {
                self.socket.send(self.io, &msg.from, packet) catch |e| {
                    if (e == std.Io.Cancelable.Canceled) break;
                    continue;
                };
            }
        }
    }

    fn nextNonce(self: *Self) [12]u8 {
        self.nonce += 1;
        return @bitCast(self.nonce);
    }

    fn nextRequestId(self: *Self) [8]u8 {
        self.nonce += 1;
        return @bitCast(@as(u64, @truncate(self.nonce)));
    }

    fn handlePacket(self: *Self, buf: []u8, from: std.Io.net.IpAddress) !?[]u8 {
        if (buf.len < 63) return error.InputTooShort;
        const enc = Aes128.initEnc(self.id[0..16].*);

        const iv = buf[0..16];
        var masked_header = buf[16..39].*;
        std.crypto.core.modes.ctr(@TypeOf(enc), enc, &masked_header, &masked_header, iv.*, .big);
        comptime std.debug.assert(@sizeOf(StaticHeader) == masked_header.len);
        comptime std.debug.assert(@alignOf(StaticHeader) == 1);
        const header: *const StaticHeader = @ptrCast(&masked_header);

        if (!std.mem.eql(u8, &header.protocol_id, "discv5")) return error.InvalidProtocolId;
        if (!std.mem.eql(u8, &header.version, &[_]u8{ 0, 1 })) return error.InvalidVersion;
        if (header.flag > 2) return error.InvalidFlag;

        const authdata_size = std.mem.readInt(u16, &header.authdata_size, .big);
        if (buf.len < 39 + authdata_size) return error.BufferTooShort;
        std.crypto.core.modes.ctr(@TypeOf(enc), enc, buf[16 .. 39 + authdata_size], buf[16 .. 39 + authdata_size], iv.*, .big);
        const auth_data = buf[39 .. 39 + authdata_size];
        switch (@as(Flags, @enumFromInt(header.flag))) {
            .Message => {
                if (authdata_size != 32) return error.InvalidAuthDataSize;
                return try self.handleMessage(auth_data[0..32], header.nonce, buf[0 .. 39 + authdata_size], buf[39 + authdata_size ..], from);
            },
            .WhoAreYou => {
                if (authdata_size != 24) return error.InvalidAuthDataSize;
                return try self.handleWhoAreYou(header.nonce, buf[0 .. 39 + authdata_size]);
            },
            .Handshake => {
                if (authdata_size < 34) return error.InvalidAuthDataSize;
                const src_id = auth_data[0..32];
                const sig_size: usize = auth_data[32];
                const key_size: usize = auth_data[33];
                if (authdata_size < 34 + sig_size + key_size) return error.InvalidAuthDataSize;
                const id_signature = auth_data[34 .. 34 + sig_size];
                const eph_pub_key = auth_data[34 + sig_size .. 34 + sig_size + key_size];
                const record = auth_data[34 + sig_size + key_size ..];
                const msg = buf[39 + authdata_size ..];
                return try self.handleHandshake(src_id, id_signature, eph_pub_key, record, msg);
            },
        }
    }

    fn handleMessage(self: *Self, src_id: *[32]u8, nonce: [12]u8, ad: []const u8, ct: []u8, from: std.Io.net.IpAddress) !?[]u8 {
        const session = self.sessions.get(self.io, src_id.*) orelse return error.NoSession;
        if (ct.len <= Aes128Gcm.tag_length) return error.MessageTooShort;

        const pt = ct[0 .. ct.len - Aes128Gcm.tag_length];
        const tag = ct[ct.len - Aes128Gcm.tag_length ..][0..Aes128Gcm.tag_length].*;
        try Aes128Gcm.decrypt(pt, pt, tag, ad, nonce, session.read_key);

        const typ = pt[0];
        if (typ == 0 or typ > @intFromEnum(Messages.Nodes)) return error.UnknownMessage;
        const body = pt[1..];
        return switch (@as(Messages, @enumFromInt(typ))) {
            .Ping => self.handlePing(src_id.*, session.write_key, from, body),
            .Pong => handlePong(body),
            .FindNode => self.handleFindNode(src_id.*, session.write_key, body),
            .Nodes => self.handleNodes(body),
        };
    }

    fn handlePing(self: *Self, dest_id: [32]u8, write_key: [16]u8, from: std.Io.net.IpAddress, body: []const u8) !?[]u8 {
        var scratch: [256]u8 = undefined;
        var fba = std.heap.FixedBufferAllocator.init(&scratch);
        var ping: Ping = undefined;
        _ = try rlp.deserialize(Ping, fba.allocator(), body, &ping);

        // PONG reports the endpoint we observed the PING coming from.
        var ip_buf: [16]u8 = undefined;
        var ip_len: usize = undefined;
        var port: u16 = undefined;
        switch (from) {
            .ip4 => |a| {
                @memcpy(ip_buf[0..4], &a.bytes);
                ip_len = 4;
                port = a.port;
            },
            .ip6 => |a| {
                @memcpy(ip_buf[0..16], &a.bytes);
                ip_len = 16;
                port = a.port;
            },
        }

        return try self.encodePacket(dest_id, .Message, self.nextNonce(), &self.id, Pong{
            .request_id = ping.request_id,
            .enr_seq = 1,
            .ip = ip_buf[0..ip_len],
            .port = port,
        }, write_key);
    }

    fn handlePong(body: []const u8) !?[]u8 {
        _ = body;
        return null;
    }

    fn handleFindNode(self: *Self, dest_id: [32]u8, write_key: [16]u8, body: []const u8) !?[]u8 {
        _ = self;
        _ = dest_id;
        _ = write_key;
        _ = body;
        return null;
    }

    fn handleNodes(self: *Self, body: []const u8) !?[]u8 {
        var scratch: [4096]u8 = undefined;
        var fba = std.heap.FixedBufferAllocator.init(&scratch);
        var nodes: Nodes = undefined;
        _ = try rlp.deserialize(Nodes, fba.allocator(), body, &nodes);
        for (nodes.records) |rec| {
            const record = enr.decode(rec.value) catch continue;
            const pubkey, const addr = record.pubkeyAndUdp() catch continue;
            const node_id = nodeId(pubkey);
            if (self.sessions.setRecord(self.io, node_id, record)) continue;
            if (addr) |ip|
                self.initiateSession(node_id, pubkey, ip, record) catch |e| {
                    if (e == std.Io.Cancelable.Canceled) return e;
                    continue;
                };
        }

        return null;
    }

    fn handleWhoAreYou(self: *Self, request_nonce: [12]u8, challenge_data: []const u8) ![]u8 {
        const handshake = self.initiated.get(request_nonce) orelse return error.UnknownChallenge;
        defer _ = self.initiated.remove(request_nonce);
        const peer_id = nodeId(handshake.pubkey);

        var sec1: [65]u8 = undefined;
        sec1[0] = 4;
        @memcpy(sec1[1..], &handshake.pubkey);
        const dest_pubkey = (try Secp256k1.fromSec1(&sec1)).toCompressedSec1();

        const eph = Ecdsa.KeyPair.generate(self.io);
        const eph_pubkey = eph.public_key.toCompressedSec1();

        const keys = try deriveKeys(eph.secret_key.toBytes(), dest_pubkey, self.id, peer_id, challenge_data);
        const id_sig = try idSign(self.allocator, self.keypair.secret_key.toBytes(), challenge_data, eph_pubkey, peer_id);
        try self.sessions.put(self.allocator, self.io, peer_id, .{ .write_key = keys.initiator, .read_key = keys.recipient, .record = handshake.record });

        var ad: [512]u8 = undefined;
        @memcpy(ad[0..32], &self.id);
        ad[32] = id_sig.len;
        ad[33] = eph_pubkey.len;
        @memcpy(ad[34..98], &id_sig);
        @memcpy(ad[98..131], &eph_pubkey);
        @memcpy(ad[131..][0..self.record_len], self.record_buf[0..self.record_len]);
        const authdata = ad[0 .. 131 + self.record_len];

        return self.encodePacket(peer_id, .Handshake, self.nextNonce(), authdata, FindNode{
            .request_id = &self.nextRequestId(),
            .distances = &.{ 256, 255, 254, 253, 0 },
        }, keys.initiator);
    }

    fn handleHandshake(self: *Self, src_id: *[32]u8, id_signature: []u8, eph_pub_key: []u8, record: []u8, msg: []u8) !?[]u8 {
        _ = self;
        _ = src_id;
        _ = id_signature;
        _ = eph_pub_key;
        _ = record;
        _ = msg;
        return null;
    }

    fn initiateSession(self: *Self, node_id: [32]u8, pubkey: [64]u8, addr: std.Io.net.IpAddress, record: ?enr.Record) !void {
        const nonce = self.nextNonce();
        var src = self.id;
        _ = try self.socket.send(self.io, &addr, try self.encodePacket(
            node_id,
            .Message,
            nonce,
            &src,
            Ping{
                .request_id = &self.nextRequestId(),
                .enr_seq = 1,
            },
            undefined,
        ));
        if (self.initiated.size < max_initiated)
            try self.initiated.put(self.allocator, nonce, .{ .pubkey = pubkey, .record = record });
    }

    fn encodePacket(
        self: *Self,
        dest_id: [32]u8,
        flag: Flags,
        nonce: [12]u8,
        authdata: []const u8,
        message: anytype,
        key: [16]u8,
    ) ![]u8 {
        std.debug.assert(authdata.len <= std.math.maxInt(u16));
        const off = 39 + authdata.len; // start of the message

        self.io.random(self.tx_buf[0..16]); // masking-iv

        const hdr = self.tx_buf[16..39];
        @memcpy(hdr[0..6], "discv5");
        std.mem.writeInt(u16, hdr[6..8], 0x0001, .big);
        hdr[8] = @intFromEnum(flag);
        @memcpy(hdr[9..21], &nonce);
        std.mem.writeInt(u16, hdr[21..23], @intCast(authdata.len), .big);

        @memcpy(self.tx_buf[39..off], authdata);

        var body = std.array_list.Managed(u8).init(self.allocator);
        defer body.deinit();
        try body.ensureTotalCapacity(1280);

        try body.append(@intFromEnum(switch (@TypeOf(message)) {
            Ping => Messages.Ping,
            Pong => Messages.Pong,
            FindNode => Messages.FindNode,
            Nodes => Messages.Nodes,
            else => unreachable,
        }));
        try rlp.serialize(@TypeOf(message), self.allocator, message, &body);

        const ct = self.tx_buf[off .. off + body.items.len];
        const tag = self.tx_buf[off + body.items.len ..][0..Aes128Gcm.tag_length];
        Aes128Gcm.encrypt(ct, tag, body.items, self.tx_buf[0..off], nonce, key);

        const enc = Aes128.initEnc(dest_id[0..16].*);
        std.crypto.core.modes.ctr(@TypeOf(enc), enc, self.tx_buf[16..off], self.tx_buf[16..off], self.tx_buf[0..16].*, .big);
        return self.tx_buf[0 .. off + body.items.len + Aes128Gcm.tag_length];
    }
};

const Sessions = struct {
    const Self = @This();
    const Session = struct { read_key: [16]u8, write_key: [16]u8, record: ?enr.Record };

    lock: std.Io.Mutex = .init,
    map: std.AutoHashMapUnmanaged([32]u8, Session) = .empty,

    fn get(self: *Self, io: std.Io, node_id: [32]u8) ?Session {
        self.lock.lockUncancelable(io);
        defer self.lock.unlock(io);
        return self.map.get(node_id);
    }

    fn put(self: *Self, allocator: std.mem.Allocator, io: std.Io, node_id: [32]u8, session: Session) !void {
        self.lock.lockUncancelable(io);
        defer self.lock.unlock(io);
        if (self.map.size < max_sessions or self.map.contains(node_id))
            try self.map.put(allocator, node_id, session);
    }

    fn setRecord(self: *Self, io: std.Io, node_id: [32]u8, record: enr.Record) bool {
        self.lock.lockUncancelable(io);
        defer self.lock.unlock(io);
        if (self.map.getEntry(node_id)) |session| {
            session.value_ptr.record = record;
            return true;
        }
        return false;
    }

    pub fn fillRecords(self: *Self, io: std.Io, out: []enr.Record) []enr.Record {
        self.lock.lockUncancelable(io);
        defer self.lock.unlock(io);
        if (self.map.size == 0 or out.len == 0) return out[0..0];

        const start: u64 = @as(u64, @intCast(std.Io.Clock.now(.real, io).toSeconds())) % self.map.size;
        var count: usize = 0;

        var i: u64 = 0;
        var it = self.map.valueIterator();
        while (it.next()) |s| : (i += 1) {
            if (i < start) continue;
            if (s.record) |r| {
                out[count] = r;
                count += 1;
                if (count == out.len) return out[0..count];
            }
        }
        i = 0;
        var it2 = self.map.valueIterator();
        while (it2.next()) |s| : (i += 1) {
            if (i >= start) break;
            if (s.record) |r| {
                out[count] = r;
                count += 1;
                if (count == out.len) return out[0..count];
            }
        }
        return out[0..count];
    }
};

fn nodeId(pubkey: [64]u8) [32]u8 {
    var id: [32]u8 = undefined;
    std.crypto.hash.sha3.Keccak256.hash(&pubkey, &id, .{});
    return id;
}

fn ecdh(pubkey: [33]u8, seckey: [32]u8) ![33]u8 {
    const p = try Secp256k1.fromSec1(&pubkey);
    return (try p.mul(seckey, .big)).toCompressedSec1();
}

fn deriveKeys(
    ephemeral_key: [32]u8,
    dest_pubkey: [33]u8,
    node_id_a: [32]u8,
    node_id_b: [32]u8,
    challenge_data: []const u8,
) !struct { initiator: [16]u8, recipient: [16]u8 } {
    const secret = try ecdh(dest_pubkey, ephemeral_key);
    const prk = HkdfSha256.extract(challenge_data, &secret);

    var info: [26 + 32 + 32]u8 = undefined;
    @memcpy(info[0..26], "discovery v5 key agreement");
    @memcpy(info[26..58], &node_id_a);
    @memcpy(info[58..90], &node_id_b);

    var okm: [32]u8 = undefined;
    HkdfSha256.expand(&okm, &info, prk);
    return .{ .initiator = okm[0..16].*, .recipient = okm[16..32].* };
}

fn idSign(
    allocator: std.mem.Allocator,
    static_key: [32]u8,
    challenge_data: []const u8,
    ephemeral_pubkey: [33]u8,
    node_id_b: [32]u8,
) ![64]u8 {
    const secp256k1_order: u256 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
    const input = try idSignatureInput(allocator, challenge_data, ephemeral_pubkey, node_id_b);
    defer allocator.free(input);

    const kp = try Ecdsa.KeyPair.fromSecretKey(try Ecdsa.SecretKey.fromBytes(static_key));
    var sig = (try kp.sign(input, null)).toBytes();

    const s = std.mem.readInt(u256, sig[32..64], .big);
    if (s > secp256k1_order / 2) std.mem.writeInt(u256, sig[32..64], secp256k1_order - s, .big);
    return sig;
}

fn idSignatureInput(
    allocator: std.mem.Allocator,
    challenge_data: []const u8,
    ephemeral_pubkey: [33]u8,
    node_id_b: [32]u8,
) ![]u8 {
    const prefix = "discovery v5 identity proof";
    const input = try allocator.alloc(u8, prefix.len + challenge_data.len + 33 + 32);
    @memcpy(input[0..prefix.len], prefix);
    @memcpy(input[prefix.len..][0..challenge_data.len], challenge_data);
    @memcpy(input[prefix.len + challenge_data.len ..][0..33], &ephemeral_pubkey);
    @memcpy(input[prefix.len + challenge_data.len + 33 ..][0..32], &node_id_b);
    return input;
}

fn idVerify(
    allocator: std.mem.Allocator,
    signer_pubkey: [33]u8,
    challenge_data: []const u8,
    ephemeral_pubkey: [33]u8,
    node_id_b: [32]u8,
    id_signature: [64]u8,
) !void {
    const input = try idSignatureInput(allocator, challenge_data, ephemeral_pubkey, node_id_b);
    defer allocator.free(input);

    const pk = try Ecdsa.PublicKey.fromSec1(&signer_pubkey);
    try Ecdsa.Signature.fromBytes(id_signature).verify(input, pk);
}

fn h(comptime s: []const u8) [s.len / 2]u8 {
    var out: [s.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}

test "ecdh" {
    const shared = try ecdh(
        h("039961e4c2356d61bedb83052c115d311acb3a96f5777296dcf297351130266231"),
        h("fb757dc581730490a1d7a00deea65e9b1936924caaea8f44d476014856b68736"),
    );
    try std.testing.expectEqual(
        h("033b11a2a1f214567e1537ce5e509ffd9b21373247f2a3ff6841f4976f53165e7e"),
        shared,
    );
}

test "key derivation" {
    const cd = h("000000000000000000000000000000006469736376350001010102030405060708090a0b0c00180102030405060708090a0b0c0d0e0f100000000000000000");
    const keys = try deriveKeys(
        h("fb757dc581730490a1d7a00deea65e9b1936924caaea8f44d476014856b68736"),
        h("0317931e6e0840220642f230037d285d122bc59063221ef3226b1f403ddc69ca91"),
        h("aaaa8419e9f49d0083561b48287df592939a8d19947d8c0ef88f2a4856a69fbb"),
        h("bbbb9d047f0488c0b5a93c1c3f2d8bafc7c8ff337024a55434a0d0555de64db9"),
        &cd,
    );
    try std.testing.expectEqual(h("dccc82d81bd610f4f76d3ebe97a40571"), keys.initiator);
    try std.testing.expectEqual(h("ac74bb8773749920b0d3a8881c173ec5"), keys.recipient);
}

test "id signature" {
    const alloc = std.testing.allocator;
    const cd = h("000000000000000000000000000000006469736376350001010102030405060708090a0b0c00180102030405060708090a0b0c0d0e0f100000000000000000");
    const static_key = h("fb757dc581730490a1d7a00deea65e9b1936924caaea8f44d476014856b68736");
    const eph_pub = h("039961e4c2356d61bedb83052c115d311acb3a96f5777296dcf297351130266231");
    const id_b = h("bbbb9d047f0488c0b5a93c1c3f2d8bafc7c8ff337024a55434a0d0555de64db9");
    const kat = h("94852a1e2318c4e5e9d422c98eaf19d1d90d876b29cd06ca7cb7546d0fff7b484fe86c09a064fe72bdbef73ba8e9c34df0cd2b53e9d65528c2c7f336d5dfc6e6");

    const kp = try Ecdsa.KeyPair.fromSecretKey(try Ecdsa.SecretKey.fromBytes(static_key));
    const signer_pub = kp.public_key.p.toCompressedSec1();

    try idVerify(alloc, signer_pub, &cd, eph_pub, id_b, kat);

    const sig = try idSign(alloc, static_key, &cd, eph_pub, id_b);
    try idVerify(alloc, signer_pub, &cd, eph_pub, id_b, sig);
}

test "aes-gcm" {
    const ct_tag = h("a5d12a2d94b8ccb3ba55558229867dc13bfa3648");
    var out: [4]u8 = undefined;
    var tag: [16]u8 = undefined;
    Aes128Gcm.encrypt(
        &out,
        &tag,
        &h("01c20101"),
        &h("93a7400fa0d6a694ebc24d5cf570f65d04215b6ac00757875e3f3a5f42107903"),
        h("27b5af763c446acd2749fe8e"),
        h("9f2d77db7004bf8a1a85107ac686990b"),
    );
    try std.testing.expectEqualSlices(u8, ct_tag[0..4], &out);
    try std.testing.expectEqualSlices(u8, ct_tag[4..20], &tag);
}

test "aes-ctr masking round-trips" {
    const key = h("9f2d77db7004bf8a1a85107ac686990b");
    const iv = h("0102030405060708090a0b0c0d0e0f10");
    const header = h("6469736376350001000102030405060708090a0b0c0020");

    var buf = header;
    const enc = Aes128.initEnc(key);
    std.crypto.core.modes.ctr(@TypeOf(enc), enc, &buf, &buf, iv, .big);
    try std.testing.expect(!std.mem.eql(u8, &header, &buf));
    const dec = Aes128.initEnc(key);
    std.crypto.core.modes.ctr(@TypeOf(dec), dec, &buf, &buf, iv, .big);
    try std.testing.expectEqualSlices(u8, &header, &buf);
}
