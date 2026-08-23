const std = @import("std");
const rlpx = @import("rlpx.zig");
const enr = @import("enr.zig");
const IdFilter = @import("../forks.zig").IdFilter;
const Blockchain = @import("../node/blockchain.zig").Blockchain;

pub const Dialer = struct {
    server: *rlpx.Server,
    filter: *const IdFilter,
    bc: *Blockchain,

    pub fn init(server: *rlpx.Server, filter: *const IdFilter, bc: *Blockchain) Dialer {
        return .{
            .server = server,
            .filter = filter,
            .bc = bc,
        };
    }

    pub fn dial(self: *const Dialer, io: std.Io, record: enr.Record) void {
        const head = self.bc.headHeader() catch return;
        const remote = record.eth orelse return;
        if (self.filter.check(remote, head.number, head.timestamp)) {
            _ = io.async(rlpx.Server.dial, .{ self.server, record });
        }
    }
};
