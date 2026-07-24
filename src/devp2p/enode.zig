const std = @import("std");

pub const Enode = struct {
    pubkey: [64]u8,
    addr: std.Io.net.IpAddress,

    pub fn parse(s: []const u8) !Enode {
        const uri = try std.Uri.parse(s);
        if (!std.mem.eql(u8, uri.scheme, "enode")) return error.InvalidSchema;

        const user = uri.user orelse return error.MissingPubkey;
        const hex = componentRaw(user);
        if (hex.len != 128) return error.BadPubkeyLength;
        var pubkey: [64]u8 = undefined;
        _ = try std.fmt.hexToBytes(&pubkey, hex);

        const host = uri.host orelse return error.MissingHost;

        var port = uri.port orelse return error.MissingPort;
        if (uri.query) |q| {
            const query = componentRaw(q);
            if (std.mem.indexOf(u8, query, "discport=")) |d| {
                const v = query[d + "discport=".len ..];
                const end = std.mem.indexOfScalar(u8, v, '&') orelse v.len;
                port = try std.fmt.parseInt(u16, v[0..end], 10);
            }
        }

        return .{
            .pubkey = pubkey,
            .addr = try std.Io.net.IpAddress.parse(componentRaw(host), port),
        };
    }

    fn componentRaw(c: std.Uri.Component) []const u8 {
        return switch (c) {
            inline else => |v| v,
        };
    }
};

test "parse" {
    const s = "enode://2c82017536b1b74b62aa2a81769f4a1213ac9edd3a1df43af5fd008f3305e92bfd9351db9881c9c09de2afc79d3f7f6c271cf2f7231f9021926c0674dc02035c@159.223.116.60:4437?discport=30303";
    const e = try Enode.parse(s);
    try std.testing.expectEqual([4]u8{ 159, 223, 116, 60 }, e.addr.ip4.bytes);
    try std.testing.expectEqual(@as(u16, 30303), e.addr.ip4.port);
    try std.testing.expectEqual(@as(u8, 0x2c), e.pubkey[0]);
    try std.testing.expectEqual(@as(u8, 0x5c), e.pubkey[63]);
}
