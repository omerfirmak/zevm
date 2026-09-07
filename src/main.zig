const std = @import("std");
const discv5 = @import("devp2p/discv5.zig");
const rlpx = @import("devp2p/rlpx.zig");
const proto = @import("devp2p/proto.zig");
const eth = @import("devp2p/eth.zig");
const snap = @import("devp2p/snap.zig");
const enr = @import("devp2p/enr.zig");
const bootnodes = @import("devp2p/bootnodes.zig");
const Dialer = @import("devp2p/dialer.zig").Dialer;
const SlabAllocator = @import("devp2p/allocator.zig").SlabAllocator;
const Record = @import("devp2p/enr.zig").Record;
const forks = @import("forks.zig");
const Blockchain = @import("node/blockchain.zig").Blockchain;
const Downloader = @import("node/downloader.zig").Downloader;
const FileStorage = @import("db/file.zig").Storage;

pub const std_options: std.Options = .{
    .log_level = .debug,
};

pub fn main(init: std.process.Init) !void {
    const kp = std.crypto.sign.ecdsa.EcdsaSecp256k1Sha256.KeyPair.generate(init.io);

    var slabs = SlabAllocator.init(init.arena.allocator());

    const datadir = try std.Io.Dir.cwd().createDirPathOpen(init.io, "datadir", .{});
    var path: [2048]u8 = undefined;
    const path_len = try datadir.realPath(init.io, &path);

    var fs = try FileStorage.init(init.io, slabs.allocator(), path[0..path_len]);
    var bc = try Blockchain.init(
        init.io,
        slabs.allocator(),
        @import("node/blockchain.zig").mainnet_config,
        &fs,
    );

    var id_filter = forks.IdFilter.init(bc.genesisHash(), &bc.cfg.fork_schedule);
    const genesis_head_header = try bc.headHeader();

    var ethproto = try eth.Provider.init(slabs.allocator());
    ethproto.hello = .{
        .status = .{
            .protocol_version = 69,
            .network_id = bc.chainId(),
            .genesis = bc.genesisHash(),
            .fork_id = id_filter.currentId(genesis_head_header.number, genesis_head_header.timestamp),
            .earliest_block = 0,
            .latest_block = (try bc.head()).number,
            .latest_block_hash = (try bc.head()).hash,
        },
    };
    var snapproto = try snap.Provider.init(slabs.allocator());
    var caps = [2]rlpx.RegisteredCapability{
        ethproto.register(),
        snapproto.register(),
    };
    var rlpx_server = try rlpx.Server.init(slabs.allocator(), init.io, kp, 30303, &caps);
    defer rlpx_server.deinit();
    ethproto.server = &rlpx_server;
    snapproto.server = &rlpx_server;

    var rlpx_thread = try init.io.concurrent(rlpx.Server.run, .{&rlpx_server});
    defer rlpx_thread.cancel(init.io) catch {};

    const dialer = Dialer.init(&rlpx_server, &id_filter, &bc);

    var server = try discv5.Server.init(
        slabs.allocator(),
        init.io,
        kp,
        33034,
        try bootnodes.parse(init.arena.allocator(), &bootnodes.mainnet),
        &dialer,
    );
    var discv_thread = try init.io.concurrent(discv5.Server.run, .{&server});
    defer discv_thread.cancel(init.io) catch {};

    var downloader = try Downloader.init(
        init.io,
        slabs.allocator(),
        &bc,
        &ethproto,
        &snapproto,
    );

    try downloader.run();
}
