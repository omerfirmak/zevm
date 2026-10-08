const std = @import("std");
const jsonrpc = @import("jsonrpc.zig");
const jwt = @import("jwt.zig");

pub const HttpServer = struct {
    const Self = @This();

    const io_buf_len = 8 * 1024;
    const max_body_len = 1024 * 1024;

    io: std.Io,
    arena: std.heap.ArenaAllocator,
    rpc: *const jsonrpc.Server,
    listener: std.Io.net.Server,
    jwt_secret: ?jwt.Secret = null,

    pub fn init(
        io: std.Io,
        allocator: std.mem.Allocator,
        rpc: *const jsonrpc.Server,
        addr: std.Io.net.IpAddress,
    ) !Self {
        return .{
            .io = io,
            .arena = .init(allocator),
            .rpc = rpc,
            .listener = try addr.listen(io, .{ .reuse_address = true }),
        };
    }

    pub fn with_auth(self: Self, secret: jwt.Secret) Self {
        var s = self;
        s.jwt_secret = secret;
        return s;
    }

    pub fn deinit(self: *Self) void {
        self.listener.deinit(self.io);
        self.arena.deinit();
    }

    pub fn run(self: *Self) !void {
        while (true) try self.serveOne();
    }

    pub fn serveOne(self: *Self) !void {
        const stream = self.listener.accept(self.io) catch |e| switch (e) {
            error.Canceled, error.SocketNotListening => return e,
            else => return,
        };
        defer stream.close(self.io);
        defer _ = self.arena.reset(.retain_capacity);
        self.serve(stream) catch {};
    }

    fn serve(self: *Self, stream: std.Io.net.Stream) !void {
        const allocator = self.arena.allocator();
        var in_buf: [io_buf_len]u8 = undefined;
        var out_buf: [io_buf_len]u8 = undefined;
        var reader = stream.reader(self.io, &in_buf);
        var writer = stream.writer(self.io, &out_buf);
        var http = std.http.Server.init(&reader.interface, &writer.interface);

        var request = try http.receiveHead();
        if (request.head.method != .POST) {
            return request.respond("", .{ .status = .method_not_allowed, .keep_alive = false });
        }

        if (self.jwt_secret) |*secret| {
            const now = std.Io.Clock.real.now(self.io).toSeconds();
            const authorized = if (bearerToken(&request)) |token|
                jwt.verify(allocator, secret, token, now) catch {
                    return request.respond("", .{ .status = .internal_server_error, .keep_alive = false });
                }
            else
                false;
            if (!authorized) {
                return request.respond("", .{ .status = .unauthorized, .keep_alive = false });
            }
        }

        const body_reader = try request.readerExpectContinue(&.{});
        const body = body_reader.allocRemaining(allocator, .limited(max_body_len)) catch |e| switch (e) {
            error.StreamTooLong => return request.respond("", .{ .status = .payload_too_large, .keep_alive = false }),
            else => return e,
        };

        const response = self.rpc.handle(self.io, allocator, body) catch {
            return request.respond("", .{ .status = .internal_server_error, .keep_alive = false });
        };

        try request.respond(response.raw, .{
            .keep_alive = false,
            .extra_headers = &.{.{ .name = "content-type", .value = "application/json" }},
        });
    }
};

fn bearerToken(request: *const std.http.Server.Request) ?[]const u8 {
    const prefix = "Bearer ";
    var headers = request.iterateHeaders();
    while (headers.next()) |header| {
        if (!std.ascii.eqlIgnoreCase(header.name, "authorization")) continue;
        if (header.value.len < prefix.len or !std.ascii.eqlIgnoreCase(header.value[0..prefix.len], prefix)) return null;
        return std.mem.trim(u8, header.value[prefix.len..], " ");
    }
    return null;
}
