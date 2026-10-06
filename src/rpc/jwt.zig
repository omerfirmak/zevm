const std = @import("std");

const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
const b64 = std.base64.url_safe_no_pad;

pub const Secret = [32]u8;

const max_iat_drift = 60;

const default_file_name = "jwt.hex";

pub fn loadOrCreateSecret(io: std.Io, datadir: std.Io.Dir, path: ?[]const u8) !Secret {
    const dir: std.Io.Dir, const sub_path = if (path) |p| .{ .cwd(), p } else .{ datadir, default_file_name };

    var buf: [128]u8 = undefined;
    if (dir.readFile(io, sub_path, &buf)) |contents| {
        return parseSecret(contents) catch |e| {
            std.log.err("invalid JWT secret in {s}: {}", .{ sub_path, e });
            return e;
        };
    } else |e| switch (e) {
        error.FileNotFound => {},
        else => return e,
    }

    var secret: Secret = undefined;
    io.random(&secret);
    const hex = std.fmt.bytesToHex(secret, .lower);
    try dir.writeFile(io, .{
        .sub_path = sub_path,
        .data = &hex,
        .flags = .{ .exclusive = true, .permissions = .fromMode(0o600) },
    });
    std.log.info("generated JWT secret at {s}", .{sub_path});
    return secret;
}

pub fn parseSecret(contents: []const u8) !Secret {
    var hex = std.mem.trim(u8, contents, &std.ascii.whitespace);
    if (std.ascii.startsWithIgnoreCase(hex, "0x")) hex = hex[2..];
    if (hex.len != 2 * @sizeOf(Secret)) return error.InvalidSecretLength;
    var secret: Secret = undefined;
    _ = try std.fmt.hexToBytes(&secret, hex);
    return secret;
}

pub fn verify(allocator: std.mem.Allocator, secret: *const Secret, token: []const u8, now: i64) std.mem.Allocator.Error!bool {
    const sig_start = std.mem.lastIndexOfScalar(u8, token, '.') orelse return false;
    const signing_input = token[0..sig_start];
    const sig_b64 = token[sig_start + 1 ..];
    const payload_start = std.mem.indexOfScalar(u8, signing_input, '.') orelse return false;
    const header_b64 = signing_input[0..payload_start];
    const payload_b64 = signing_input[payload_start + 1 ..];

    var sig: [HmacSha256.mac_length]u8 = undefined;
    if (sig_b64.len != b64.Encoder.calcSize(sig.len)) return false;
    b64.Decoder.decode(&sig, sig_b64) catch return false;
    var expected: [HmacSha256.mac_length]u8 = undefined;
    HmacSha256.create(&expected, signing_input, secret);
    if (!std.crypto.timing_safe.eql([HmacSha256.mac_length]u8, sig, expected)) return false;

    const header = try parseSegment(struct { alg: []const u8 }, allocator, header_b64) orelse return false;
    defer header.deinit();
    if (!std.mem.eql(u8, header.value.alg, "HS256")) return false;

    const claims = try parseSegment(struct { iat: NumericDate, exp: ?NumericDate = null }, allocator, payload_b64) orelse return false;
    defer claims.deinit();
    const now_f: f64 = @floatFromInt(now);
    if (claims.value.exp) |exp| {
        if (now_f >= exp.seconds) return false;
    }
    const iat = claims.value.iat.seconds;
    return iat >= now_f - max_iat_drift and iat <= now_f + max_iat_drift;
}

// RFC 7519 NumericDate
const NumericDate = struct {
    seconds: f64,

    pub fn jsonParse(allocator: std.mem.Allocator, source: anytype, options: std.json.ParseOptions) !NumericDate {
        _ = allocator;
        _ = options;
        switch (try source.next()) {
            .number => |text| {
                const seconds = try std.fmt.parseFloat(f64, text);
                if (!std.math.isFinite(seconds)) return error.InvalidNumber;
                return .{ .seconds = seconds };
            },
            else => return error.UnexpectedToken,
        }
    }
};

fn parseSegment(comptime T: type, allocator: std.mem.Allocator, segment: []const u8) std.mem.Allocator.Error!?std.json.Parsed(T) {
    const decoded_len = b64.Decoder.calcSizeForSlice(segment) catch return null;
    const decoded = try allocator.alloc(u8, decoded_len);
    defer allocator.free(decoded);
    b64.Decoder.decode(decoded, segment) catch return null;
    return std.json.parseFromSlice(T, allocator, decoded, .{ .ignore_unknown_fields = true, .allocate = .alloc_always }) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return null,
    };
}

test "verify" {
    const allocator = std.testing.allocator;
    const secret = try parseSecret("0x" ++ @as([64]u8, @splat('1')) ++ "\n");
    const other = try parseSecret(&@as([64]u8, @splat('2')));
    const now = 1_700_000_000;

    // {"alg":"HS256","typ":"JWT"}.{"iat":1700000030,"id":"cl"}
    const ok = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE3MDAwMDAwMzAsImlkIjoiY2wifQ.c9lQrzmCQlVPDZXbyz7ZIoMSgzTL4bTi6hbY99vxuBY";
    try std.testing.expect(try verify(allocator, &secret, ok, now));
    try std.testing.expect(!try verify(allocator, &other, ok, now));
    try std.testing.expect(!try verify(allocator, &secret, ok, now + 91));
    try std.testing.expect(!try verify(allocator, &secret, ok, now - 31));
    try std.testing.expect(!try verify(allocator, &secret, ok[0 .. ok.len - 1], now));

    // {"alg":"none"}.{"iat":1700000000}
    const none = "eyJhbGciOiJub25lIn0.eyJpYXQiOjE3MDAwMDAwMDB9.hYpBZ0FoFCBvRZZb0eUR019U3Twjh1p7wUrnozUIx8I";
    try std.testing.expect(!try verify(allocator, &secret, none, now));

    // {"alg":"HS256","typ":"JWT"}.{}
    const no_iat = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.qicxnSm7VrPzmIa7NiDC7854ZBXZFibOdWp3Bi-SezU";
    try std.testing.expect(!try verify(allocator, &secret, no_iat, now));

    // {"alg":"HS256","typ":"JWT"}.{"iat":1700000000.5}
    const float_iat = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE3MDAwMDAwMDAuNX0.WsL6UBJktoF6wJk9KzQAfIk4z1s1h809lvzyIjVZotc";
    try std.testing.expect(try verify(allocator, &secret, float_iat, now));

    // {"alg":"HS256","typ":"JWT"}.{"iat":"1700000000"}
    const string_iat = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOiIxNzAwMDAwMDAwIn0.O_8VOaNdME3TITt6J8fLX5l9rhaGwayBQPnx1ZALGnI";
    try std.testing.expect(!try verify(allocator, &secret, string_iat, now));

    // {"alg":"HS256","typ":"JWT"}.{"iat":1700000000,"exp":1700000000}
    const expired = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE3MDAwMDAwMDAsImV4cCI6MTcwMDAwMDAwMH0.KNzcgzh9dIt-gQwy6Ly7cattEh7Hp7CYGKA32K5CKuA";
    try std.testing.expect(!try verify(allocator, &secret, expired, now));

    // {"alg":"HS256","typ":"JWT"}.{"iat":1700000000,"exp":1700000001}
    const not_expired = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE3MDAwMDAwMDAsImV4cCI6MTcwMDAwMDAwMX0.RqFFgZi3bNv5RrTZXbvhYITIusMT6Lnf7_F8FOTXiqQ";
    try std.testing.expect(try verify(allocator, &secret, not_expired, now));

    try std.testing.expect(!try verify(allocator, &secret, "", now));
    try std.testing.expect(!try verify(allocator, &secret, "a.b.c.d", now));
}

test "parseSecret" {
    try std.testing.expectError(error.InvalidSecretLength, parseSecret("11"));
    try std.testing.expectError(error.InvalidCharacter, parseSecret(&@as([64]u8, @splat('z'))));
}
