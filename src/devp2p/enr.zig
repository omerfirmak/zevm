const std = @import("std");
const rlp = @import("rlp");
const Enode = @import("enode.zig").Enode;
const ForkId = @import("../forks.zig").Id;
const Secp256k1 = std.crypto.ecc.Secp256k1;
const Ecdsa = std.crypto.sign.ecdsa.EcdsaSecp256k1Sha256;
const Keccak256 = std.crypto.hash.sha3.Keccak256;

const secp256k1_order: u256 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

pub const Record = struct {
    seq: u64,
    pubkey: [33]u8,
    node_id: [32]u8,
    ip4: ?[4]u8 = null,
    udp: ?u16 = null,
    tcp: ?u16 = null,
    eth: ?ForkId = null,

    pub fn uncompressedPubkey(self: *const Record) ![64]u8 {
        const unc = (try Secp256k1.fromSec1(&self.pubkey)).toUncompressedSec1();
        return unc[1..65].*;
    }

    pub fn pubkeyAndUdp(self: *const Record) !struct { [64]u8, ?std.Io.net.IpAddress } {
        var addr: ?std.Io.net.IpAddress = null;
        if (self.ip4) |ip| {
            if (self.udp) |port| {
                addr = std.Io.net.IpAddress{ .ip4 = .{ .bytes = ip, .port = port } };
            }
        }
        return .{ try self.uncompressedPubkey(), addr };
    }

    pub fn tcpAddr(self: *const Record) ?std.Io.net.IpAddress {
        if (self.ip4) |ip| {
            if (self.tcp) |port| {
                return std.Io.net.IpAddress{ .ip4 = .{ .bytes = ip, .port = port } };
            }
        }
        return null;
    }
};

pub fn decode(bytes: []const u8) !Record {
    var scratch: [2048]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&scratch);
    const alloc = fba.allocator();

    var items: [][]const u8 = undefined;
    _ = try rlp.deserialize([][]const u8, alloc, bytes, &items);
    if (items.len < 2 or items.len % 2 != 0) return error.MalformedRecord;

    const sig = items[0];
    if (sig.len != 64) return error.InvalidSignature;
    if (items[1].len > 8) return error.InvalidSeq;

    var rec: Record = .{
        .seq = std.mem.readVarInt(u64, items[1], .big),
        .pubkey = undefined,
        .node_id = undefined,
    };

    var have_pubkey = false;
    var i: usize = 2;
    while (i + 1 < items.len) : (i += 2) {
        const k = items[i];
        const v = items[i + 1];
        if (std.mem.eql(u8, k, "id")) {
            if (!std.mem.eql(u8, v, "v4")) return error.UnsupportedIdentityScheme;
        } else if (std.mem.eql(u8, k, "secp256k1")) {
            if (v.len != 33) return error.InvalidPubkey;
            rec.pubkey = v[0..33].*;
            have_pubkey = true;
        } else if (std.mem.eql(u8, k, "ip")) {
            if (v.len == 4) rec.ip4 = v[0..4].*;
        } else if (std.mem.eql(u8, k, "udp")) {
            if (v.len > 2) return error.InvalidPort;
            rec.udp = std.mem.readVarInt(u16, v, .big);
        } else if (std.mem.eql(u8, k, "tcp")) {
            if (v.len > 2) return error.InvalidPort;
            rec.tcp = std.mem.readVarInt(u16, v, .big);
        } else if (std.mem.eql(u8, k, "eth")) {
            var id: ForkId = undefined;
            _ = rlp.deserialize(ForkId, undefined, v, &id) catch continue;
            rec.eth = id;
        }
    }
    if (!have_pubkey) return error.MissingPubkey;

    const rest = bytes[@intFromPtr(sig.ptr) - @intFromPtr(bytes.ptr) + sig.len ..];
    var content = std.array_list.Managed(u8).init(alloc);
    try rlp.serialize(rlp.RawValue, alloc, .{ .list = &.{.{ .value = rest }} }, &content);
    var hash: [32]u8 = undefined;
    Keccak256.hash(content.items, &hash, .{});

    const pk = try Ecdsa.PublicKey.fromSec1(&rec.pubkey);
    try Ecdsa.Signature.fromBytes(sig[0..64].*).verifyPrehashed(hash, pk);

    const unc = (try Secp256k1.fromSec1(&rec.pubkey)).toUncompressedSec1();
    Keccak256.hash(unc[1..65], &rec.node_id, .{});
    return rec;
}

fn rlpItem(alloc: std.mem.Allocator, comptime T: type, val: T) ![]const u8 {
    var l = std.array_list.Managed(u8).init(alloc);
    try rlp.serialize(T, alloc, val, &l);
    return l.items;
}

pub fn encode(
    buf: *[300]u8,
    static_key: [32]u8,
    seq: u64,
    ip4: ?[4]u8,
    udp: ?u16,
    tcp: ?u16,
) ![]u8 {
    var scratch: [4096]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&scratch);
    const alloc = fba.allocator();

    const kp = try Ecdsa.KeyPair.fromSecretKey(try Ecdsa.SecretKey.fromBytes(static_key));
    const pubkey = kp.public_key.toCompressedSec1();
    var sig: [64]u8 = undefined;

    var elems = std.array_list.Managed(rlp.RawValue).init(alloc);
    try elems.append(.{ .value = try rlpItem(alloc, u64, seq) });
    try elems.append(.{ .value = try rlpItem(alloc, []const u8, "id") });
    try elems.append(.{ .value = try rlpItem(alloc, []const u8, "v4") });
    if (ip4) |ip| {
        try elems.append(.{ .value = try rlpItem(alloc, []const u8, "ip") });
        try elems.append(.{ .value = try rlpItem(alloc, [4]u8, ip) });
    }
    try elems.append(.{ .value = try rlpItem(alloc, []const u8, "secp256k1") });
    try elems.append(.{ .value = try rlpItem(alloc, [33]u8, pubkey) });
    if (tcp) |p| {
        try elems.append(.{ .value = try rlpItem(alloc, []const u8, "tcp") });
        try elems.append(.{ .value = try rlpItem(alloc, u16, p) });
    }
    if (udp) |p| {
        try elems.append(.{ .value = try rlpItem(alloc, []const u8, "udp") });
        try elems.append(.{ .value = try rlpItem(alloc, u16, p) });
    }

    var content = std.array_list.Managed(u8).init(alloc);
    try rlp.serialize(rlp.RawValue, alloc, .{ .list = elems.items }, &content);
    var hash: [32]u8 = undefined;
    Keccak256.hash(content.items, &hash, .{});

    sig = (try kp.signPrehashed(hash, null)).toBytes();
    const s = std.mem.readInt(u256, sig[32..64], .big);
    if (s > secp256k1_order / 2) std.mem.writeInt(u256, sig[32..64], secp256k1_order - s, .big);
    try elems.insert(0, .{ .value = try rlpItem(alloc, []const u8, &sig) });

    var out = std.array_list.Managed(u8).init(alloc);
    try rlp.serialize(rlp.RawValue, alloc, .{ .list = elems.items }, &out);
    if (out.items.len > buf.len) return error.RecordTooLarge;
    @memcpy(buf[0..out.items.len], out.items);
    return buf[0..out.items.len];
}

fn h(comptime s: []const u8) [s.len / 2]u8 {
    var out: [s.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}

test "decode" {
    const bytes = h("f884b8407098ad865b00a582051940cb9cf36836572411a47278783077011599ed5cd16b76f2635f4e234738f30813a89eb9137e3e3df5266e3a1f11df72ecf1145ccb9c0182696482763482697084" ++
        "7f00000189736563703235366b31a103ca634cae0d49acb401d8a4c6b6fe8c55b70d115bf400769cc1400f3258cd313883756470" ++
        "82765f");
    const rec = try decode(&bytes);

    try std.testing.expectEqual(@as(u64, 1), rec.seq);
    try std.testing.expectEqual([4]u8{ 0x7f, 0, 0, 1 }, rec.ip4.?);
    try std.testing.expectEqual(@as(u16, 30303), rec.udp.?);
    try std.testing.expectEqualSlices(u8, &h("03ca634cae0d49acb401d8a4c6b6fe8c55b70d115bf400769cc1400f3258cd3138"), &rec.pubkey);
    try std.testing.expectEqualSlices(u8, &h("a448f24c6d18e575453db13171562b71999873db5b286df957af199ec94617f7"), &rec.node_id);
}

test "reject a tampered record" {
    var bytes = h("f884b8407098ad865b00a582051940cb9cf36836572411a47278783077011599ed5cd16b76f2635f4e234738f30813a89eb9137e3e3df5266e3a1f11df72ecf1145ccb9c0182696482763482697084" ++
        "7f00000189736563703235366b31a103ca634cae0d49acb401d8a4c6b6fe8c55b70d115bf400769cc1400f3258cd313883756470" ++
        "82765f");
    bytes[bytes.len - 1] ^= 0xff;
    try std.testing.expectError(error.SignatureVerificationFailed, decode(&bytes));
}

test "encode round trip" {
    const static_key = h("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291");
    var buf: [300]u8 = undefined;
    const enc = try encode(&buf, static_key, 1, [4]u8{ 127, 0, 0, 1 }, 30303, null);

    const canonical_content = h("0182696482763482697084" ++
        "7f00000189736563703235366b31a103ca634cae0d49acb401d8a4c6b6fe8c55b70d115bf400769cc1400f3258cd31388375647082765f");
    try std.testing.expectEqualSlices(u8, &canonical_content, enc[68..]);

    const rec = try decode(enc);
    try std.testing.expectEqual(@as(u64, 1), rec.seq);
    try std.testing.expectEqual([4]u8{ 127, 0, 0, 1 }, rec.ip4.?);
    try std.testing.expectEqual(@as(u16, 30303), rec.udp.?);
    try std.testing.expectEqualSlices(u8, &h("a448f24c6d18e575453db13171562b71999873db5b286df957af199ec94617f7"), &rec.node_id);
}
