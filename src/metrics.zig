const std = @import("std");

pub const Source = struct {
    ctx: *anyopaque,
    write: *const fn (*anyopaque, *std.Io.Writer) anyerror!void,

    pub fn from(comptime T: type, ptr: *T) Source {
        return .{
            .ctx = ptr,
            .write = struct {
                fn write(ctx: *anyopaque, writer: *std.Io.Writer) anyerror!void {
                    const self: *T = @ptrCast(@alignCast(ctx));
                    return self.writeMetrics(writer);
                }
            }.write,
        };
    }
};

/// Serves `GET /metrics` in the Prometheus text exposition format.
pub const HttpServer = struct {
    const Self = @This();

    const io_buf_len = 8 * 1024;

    io: std.Io,
    arena: std.heap.ArenaAllocator,
    sources: []const Source,
    listener: std.Io.net.Server,

    pub fn init(
        io: std.Io,
        allocator: std.mem.Allocator,
        sources: []const Source,
        addr: std.Io.net.IpAddress,
    ) !Self {
        return .{
            .io = io,
            .arena = .init(allocator),
            .sources = sources,
            .listener = try addr.listen(io, .{}),
        };
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
        var in_buf: [io_buf_len]u8 = undefined;
        var out_buf: [io_buf_len]u8 = undefined;
        var reader = stream.reader(self.io, &in_buf);
        var writer = stream.writer(self.io, &out_buf);
        var http = std.http.Server.init(&reader.interface, &writer.interface);

        var request = try http.receiveHead();
        if (request.head.method != .GET) {
            return request.respond("", .{ .status = .method_not_allowed, .keep_alive = false });
        }
        const path = std.mem.sliceTo(request.head.target, '?');
        if (!std.mem.eql(u8, path, "/metrics")) {
            return request.respond("", .{ .status = .not_found, .keep_alive = false });
        }

        var body: std.Io.Writer.Allocating = .init(self.arena.allocator());
        for (self.sources) |source| {
            source.write(source.ctx, &body.writer) catch {
                return request.respond("", .{ .status = .internal_server_error, .keep_alive = false });
            };
        }

        try request.respond(body.written(), .{
            .keep_alive = false,
            .extra_headers = &.{.{ .name = "content-type", .value = "text/plain; version=0.0.4; charset=utf-8" }},
        });
    }
};
