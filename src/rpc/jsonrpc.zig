const std = @import("std");

const json_parse_err =
    \\{"jsonrpc":"2.0","error":{"code":-32600}}
;

pub const Server = struct {
    const Self = @This();
    pub const Errors = error{
        InvalidJSON,
        InvalidRequest,
        MethodNotFound,
        InvalidParams,
        InternalError,
    } || std.mem.Allocator.Error;
    pub const ErrorCodes = enum(i32) {
        InvalidJSON = -32700,
        InvalidRequest = -32600,
        MethodNotFound = -32601,
        InvalidParams = -32602,
        InternalError = -32603,
    };

    methods: std.StringHashMapUnmanaged(Handler) = .empty,

    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        self.methods.deinit(allocator);
    }

    pub fn register(
        self: *Self,
        allocator: std.mem.Allocator,
        method: []const u8,
        ctx: *anyopaque,
        comptime handler_fn: anytype,
    ) !void {
        try self.methods.put(allocator, method, Handler.init(ctx, handler_fn));
    }

    pub fn handle(self: *const Self, io: std.Io, allocator: std.mem.Allocator, json: []const u8) !RawJson {
        const parsed = std.json.parseFromSlice(Request, allocator, json, .{}) catch {
            return .{ .raw = try allocator.dupe(u8, json_parse_err) };
        };
        defer parsed.deinit();

        var resp: Response = .{ .id = parsed.value.id };

        const result = result: {
            const method = self.methods.get(parsed.value.method) orelse break :result Errors.MethodNotFound;
            break :result method.call(io, allocator, parsed.value.params);
        };

        defer resp.deinit(allocator);

        if (result) |result_json| {
            resp.result = result_json;
        } else |e| {
            resp.err = .{
                .code = @intFromEnum(switch (e) {
                    Errors.InvalidJSON => ErrorCodes.InvalidJSON,
                    Errors.InvalidRequest => ErrorCodes.InvalidRequest,
                    Errors.MethodNotFound => ErrorCodes.MethodNotFound,
                    Errors.InvalidParams => ErrorCodes.InvalidParams,
                    else => ErrorCodes.InternalError,
                }),
                .message = @errorName(e),
            };
        }

        return .{ .raw = try std.fmt.allocPrint(allocator, "{f}", .{std.json.fmt(resp, .{})}) };
    }
};

const Handler = struct {
    const Self = @This();
    const CallFn = *const fn (std.Io, std.mem.Allocator, *anyopaque, RawJson) anyerror!RawJson;

    ctx: *anyopaque,
    call_fn: CallFn,

    fn init(ctx: *anyopaque, comptime impl: anytype) Self {
        return .{
            .ctx = ctx,
            .call_fn = wrap(impl),
        };
    }

    fn call(self: *const Self, io: std.Io, allocator: std.mem.Allocator, args_json: RawJson) !RawJson {
        return self.call_fn(io, allocator, self.ctx, args_json);
    }

    fn wrap(comptime impl: anytype) CallFn {
        return struct {
            fn handler(io: std.Io, allocator: std.mem.Allocator, ctx: *anyopaque, args_json: RawJson) !RawJson {
                const FullArgs = std.meta.ArgsTuple(@TypeOf(impl));
                var args: FullArgs = undefined;

                args[0] = @ptrCast(@alignCast(ctx));
                args[1] = io;
                args[2] = allocator;

                if (args.len > 3) {
                    const JsonArgs = ExtractSubTuple(FullArgs, 3);
                    const parsed = try std.json.parseFromSlice(JsonArgs, allocator, args_json.raw, .{});
                    defer parsed.deinit();
                    inline for (3..args.len) |index| {
                        args[index] = parsed.value[index - 3];
                    }
                }

                const result = try @call(.auto, impl, args);
                const Result = @TypeOf(result);
                const actual = if (Result != void)
                    try std.fmt.allocPrint(allocator, "{f}", .{std.json.fmt(result, .{})})
                else
                    &[_]u8{};
                return .{ .raw = actual };
            }
        }.handler;
    }
};

pub const Request = struct {
    jsonrpc: []const u8,
    method: []const u8,
    params: RawJson,
    id: RawJson,
};

pub const Response = struct {
    const Self = @This();

    jsonrpc: []const u8 = "2.0",
    result: ?RawJson = null,
    err: ?struct {
        code: i32,
        message: []const u8,
    } = null,
    id: RawJson,

    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        if (self.result) |raw_json| {
            allocator.free(raw_json.raw);
        }
    }

    pub fn jsonStringify(self: *const Self, jws: anytype) !void {
        try jws.beginObject();
        try jws.objectField("jsonrpc");
        try jws.write(self.jsonrpc);
        if (self.result) |result| {
            try jws.objectField("result");
            try jws.write(result);
        }
        if (self.err) |err| {
            try jws.objectField("error");
            try jws.write(err);
        }
        if (self.id.raw.len > 0) {
            try jws.objectField("id");
            try jws.write(self.id);
        }
        try jws.endObject();
    }
};

pub const RawJson = struct {
    const Self = @This();

    raw: []const u8,

    pub fn jsonParse(
        allocator: std.mem.Allocator,
        source: anytype,
        options: std.json.ParseOptions,
    ) !Self {
        _ = allocator;
        _ = options;

        _ = try source.peekNextTokenType();
        const start_idx = source.cursor;
        try source.skipValue();
        const end_idx = source.cursor;
        return .{
            .raw = source.input[start_idx..end_idx],
        };
    }

    pub fn jsonStringify(
        self: *const Self,
        jws: anytype,
    ) !void {
        try jws.beginWriteRaw();
        try jws.writer.writeAll(self.raw);
        jws.endWriteRaw();
    }
};

fn ExtractSubTuple(comptime FullTuple: type, comptime start_idx: usize) type {
    const fields = @typeInfo(FullTuple).@"struct".fields;
    var sub_types: [fields.len - start_idx]type = undefined;
    inline for (start_idx..fields.len) |i| {
        sub_types[i - start_idx] = fields[i].type;
    }
    return @Tuple(&sub_types);
}

test "server" {
    const API = struct {
        const Self = @This();
        a: u32 = 3,
        pub fn sum(self: *Self, _: std.Io, _: std.mem.Allocator, a: u32, b: u32) !u32 {
            if (a == b) return error.No;
            return self.a + a + b;
        }
    };

    var api: API = .{};
    var server: Server = .{};
    defer server.deinit(std.testing.allocator);
    try server.register(std.testing.allocator, "sum", &api, API.sum);

    for ([_]struct {
        input: []const u8,
        expected: []const u8,
    }{
        .{
            .input =
            \\{"jsonrpc" : "2.0", "method" : "sum", "params" : [1,2], "id" : 1}
            ,
            .expected =
            \\{"jsonrpc":"2.0","result":6,"id":1}
            ,
        },
        .{
            .input =
            \\{"jsonrpc" : "2.0", "method" : "sum", "params" : [1,1], "id" : 1}
            ,
            .expected =
            \\{"jsonrpc":"2.0","error":{"code":-32603,"message":"No"},"id":1}
            ,
        },
        .{
            .input =
            \\{"jsonrpc" : "2.0", "method" : "notfound", "params" : [1,1], "id" : 1}
            ,
            .expected =
            \\{"jsonrpc":"2.0","error":{"code":-32601,"message":"MethodNotFound"},"id":1}
            ,
        },
        .{
            .input =
            \\{]
            ,
            .expected =
            \\{"jsonrpc":"2.0","error":{"code":-32600}}
            ,
        },
    }) |test_case| {
        const res = try server.handle(std.testing.io, std.testing.allocator, test_case.input);
        defer std.testing.allocator.free(res.raw);
        try std.testing.expectEqualStrings(test_case.expected, res.raw);
    }
}
