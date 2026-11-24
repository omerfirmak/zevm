// Copyright (c) 2025-2026 zevm authors
// SPDX-License-Identifier: MIT OR Apache-2.0

const std = @import("std");
const rlpx = @import("rlpx.zig");
const enr = @import("enr.zig");
const IdFilter = @import("../forks.zig").IdFilter;
const EthDb = @import("../db/eth.zig").Eth;

pub const Dialer = struct {
    server: *rlpx.Server,
    filter: *const IdFilter,
    eth_db: *EthDb,
    dials: std.Io.Group = .init,

    pub fn init(server: *rlpx.Server, filter: *const IdFilter, eth_db: *EthDb) Dialer {
        return .{
            .server = server,
            .filter = filter,
            .eth_db = eth_db,
        };
    }

    pub fn deinit(self: *Dialer, io: std.Io) void {
        self.dials.cancel(io);
    }

    pub fn dial(self: *Dialer, io: std.Io, record: enr.Record) void {
        const head = self.eth_db.headHeader() catch return;
        const remote = record.eth orelse return;
        if (record.tcpAddr() != null and
            self.filter.check(remote, head.number, head.timestamp) and
            self.server.candidatePeer(record))
        {
            self.dials.concurrent(io, dialTask, .{ self.server, record }) catch return;
        }
    }

    fn dialTask(server: *rlpx.Server, record: enr.Record) void {
        server.dial(record) catch {};
    }
};
