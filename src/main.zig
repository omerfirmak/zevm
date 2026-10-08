const std = @import("std");
const clap = @import("clap");
const discv5 = @import("devp2p/discv5.zig");
const rlpx = @import("devp2p/rlpx.zig");
const proto = @import("devp2p/proto.zig");
const eth = @import("devp2p/eth.zig");
const snap = @import("devp2p/snap.zig");
const kv = @import("db/kv.zig");
const enr = @import("devp2p/enr.zig");
const bootnodes = @import("devp2p/bootnodes.zig");
const EthDb = @import("db/eth.zig").Eth;
const Dialer = @import("devp2p/dialer.zig").Dialer;
const SlabAllocator = @import("devp2p/allocator.zig").SlabAllocator;
const Record = @import("devp2p/enr.zig").Record;
const forks = @import("forks.zig");
const blockchain = @import("node/blockchain.zig");
const Blockchain = blockchain.Blockchain;
const Downloader = @import("node/downloader.zig").Downloader;
const FileStorage = @import("db/file.zig").Storage;
const EthApi = @import("rpc/eth.zig").Eth;
const EngineApi = @import("rpc/engine.zig").Engine;
const RpcServer = @import("rpc/jsonrpc.zig").Server;
const RpcHttpServer = @import("rpc/http.zig").HttpServer;
const jwt = @import("rpc/jwt.zig");
const metrics = @import("metrics.zig");

pub const std_options: std.Options = .{
    .log_level = .info,
    .logFn = @import("log.zig").timestamped,
};

const Network = enum { glamsterdam_devnet8, mainnet, sepolia };

const params = clap.parseParamsComptime(
    \\-h, --help                Display this help and exit.
    \\-n, --network <network>   Network to join: glamsterdam_devnet8, mainnet, sepolia (default: glamsterdam_devnet8).
    \\-d, --datadir <str>       Data directory (default: datadir).
    \\    --port <u16>          RLPx TCP listening port (default: 30303).
    \\    --discovery-port <u16> discv5 UDP listening port (default: 33034).
    \\    --bootnode <str>...   Bootnode ENR, can be repeated. Replaces the network's default bootnodes.
    \\    --http-addr <str>     JSON-RPC HTTP listening address (default: 127.0.0.1).
    \\    --http-port <u16>     JSON-RPC HTTP listening port (default: 8545).
    \\    --authrpc-addr <str>  Authenticated (Engine API) RPC listening address (default: 127.0.0.1).
    \\    --authrpc-port <u16>  Authenticated (Engine API) RPC listening port (default: 8551).
    \\    --authrpc-jwtsecret <str> Path to the hex-encoded JWT secret; created if missing (default: <datadir>/jwt.hex).
    \\    --metrics-addr <str>  Prometheus metrics HTTP listening address (default: 127.0.0.1).
    \\    --metrics-port <u16>  Prometheus metrics HTTP listening port (default: 6060).
    \\
);

const parsers = .{
    .str = clap.parsers.string,
    .u16 = clap.parsers.int(u16, 10),
    .network = clap.parsers.enumeration(Network),
};

const Options = struct {
    config: blockchain.Config,
    bootnodes: []const []const u8,
    datadir: []const u8,
    port: u16,
    discovery_port: u16,
    http_addr: std.Io.net.IpAddress,
    authrpc_addr: std.Io.net.IpAddress,
    authrpc_jwtsecret: ?[]const u8,
    metrics_addr: std.Io.net.IpAddress,

    fn parse(init: std.process.Init) !?Options {
        var diag = clap.Diagnostic{};
        const res = clap.parse(clap.Help, &params, parsers, init.minimal.args, .{
            .diagnostic = &diag,
            .allocator = init.arena.allocator(),
        }) catch |err| {
            try diag.reportToFile(init.io, std.Io.File.stderr(), err);
            std.process.exit(1);
        };

        if (res.args.help != 0) {
            try clap.helpToFile(init.io, std.Io.File.stderr(), clap.Help, &params, .{});
            return null;
        }

        const network = res.args.network orelse .glamsterdam_devnet8;
        const http_addr = res.args.@"http-addr" orelse "127.0.0.1";
        const http_port = res.args.@"http-port" orelse 8545;
        const authrpc_addr = res.args.@"authrpc-addr" orelse "127.0.0.1";
        const authrpc_port = res.args.@"authrpc-port" orelse 8551;
        const metrics_addr = res.args.@"metrics-addr" orelse "127.0.0.1";
        const metrics_port = res.args.@"metrics-port" orelse 6060;
        return .{
            .config = switch (network) {
                .glamsterdam_devnet8 => blockchain.glamsterdam_devnet8_config,
                .mainnet => blockchain.mainnet_config,
                .sepolia => blockchain.sepolia_config,
            },
            .bootnodes = if (res.args.bootnode.len > 0) res.args.bootnode else switch (network) {
                .glamsterdam_devnet8 => &bootnodes.glamsterdam_devnet8,
                .mainnet => &bootnodes.mainnet,
                .sepolia => &bootnodes.sepolia,
            },
            .datadir = res.args.datadir orelse "datadir",
            .port = res.args.port orelse 30303,
            .discovery_port = res.args.@"discovery-port" orelse 33034,
            .http_addr = std.Io.net.IpAddress.parse(http_addr, http_port) catch |e| {
                std.log.err("invalid --http-addr {s}: {}", .{ http_addr, e });
                std.process.exit(1);
            },
            .authrpc_addr = std.Io.net.IpAddress.parse(authrpc_addr, authrpc_port) catch |e| {
                std.log.err("invalid --authrpc-addr {s}: {}", .{ authrpc_addr, e });
                std.process.exit(1);
            },
            .authrpc_jwtsecret = res.args.@"authrpc-jwtsecret",
            .metrics_addr = std.Io.net.IpAddress.parse(metrics_addr, metrics_port) catch |e| {
                std.log.err("invalid --metrics-addr {s}: {}", .{ metrics_addr, e });
                std.process.exit(1);
            },
        };
    }
};

fn openDataSubdir(io: std.Io, allocator: std.mem.Allocator, datadir: std.Io.Dir, sub_path: []const u8) ![]const u8 {
    var dir = try datadir.createDirPathOpen(io, sub_path, .{});
    defer dir.close(io);
    var path: [std.fs.max_path_bytes]u8 = undefined;
    const len = try dir.realPath(io, &path);
    return allocator.dupe(u8, path[0..len]);
}

pub fn main(init: std.process.Init) !void {
    const opts = try Options.parse(init) orelse return;

    const kp = std.crypto.sign.ecdsa.EcdsaSecp256k1Sha256.KeyPair.generate(init.io);

    var slabs = SlabAllocator.init(init.arena.allocator());

    var datadir = try std.Io.Dir.cwd().createDirPathOpen(init.io, opts.datadir, .{});
    defer datadir.close(init.io);
    const static_path = try openDataSubdir(init.io, init.arena.allocator(), datadir, "static");
    const mdbx_path = try openDataSubdir(init.io, init.arena.allocator(), datadir, "mdbx");

    var fs = try FileStorage.init(init.io, slabs.allocator(), static_path);
    var bc = try Blockchain.init(init.io, slabs.allocator(), opts.config, &fs);

    var id_filter = forks.IdFilter.init(bc.genesisHash(), &bc.cfg.fork_schedule);
    const genesis_head_header = try bc.headHeader();

    var ethproto = try eth.Provider.init(slabs.allocator());
    ethproto.hello = .{
        .status = .{
            .protocol_version = 71,
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
    var rlpx_server = try rlpx.Server.init(slabs.allocator(), init.io, kp, opts.port, &caps);
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
        opts.discovery_port,
        try bootnodes.parse(init.arena.allocator(), opts.bootnodes),
        &dialer,
    );
    var discv_thread = try init.io.concurrent(discv5.Server.run, .{&server});
    defer discv_thread.cancel(init.io) catch {};

    var store = try kv.Store.init(slabs.allocator(), mdbx_path);
    var eth_db = EthDb.init(&store);

    var downloader = try Downloader.init(
        init.io,
        slabs.allocator(),
        &bc,
        &eth_db,
        &ethproto,
        &snapproto,
    );

    const metrics_sources = [_]metrics.Source{
        .from(rlpx.Server, &rlpx_server),
        .from(Downloader, &downloader),
    };
    var metrics_http: metrics.HttpServer = try .init(init.io, slabs.allocator(), &metrics_sources, opts.metrics_addr);
    var metrics_thread = try init.io.concurrent(metrics.HttpServer.run, .{&metrics_http});
    defer metrics_thread.cancel(init.io) catch {};

    var eth_api: EthApi = .init(&bc, &downloader);
    var jsonrpc_server: RpcServer = .{};
    try eth_api.register(init.arena.allocator(), &jsonrpc_server);

    var jsonrpc_http: RpcHttpServer = try .init(init.io, slabs.allocator(), &jsonrpc_server, opts.http_addr);
    var rpc_thread = try init.io.concurrent(RpcHttpServer.run, .{&jsonrpc_http});
    defer rpc_thread.cancel(init.io) catch {};

    const jwt_secret = try jwt.loadOrCreateSecret(init.io, datadir, opts.authrpc_jwtsecret);
    var authrpc_server: RpcServer = .{};
    try eth_api.register(init.arena.allocator(), &authrpc_server);
    var engine_api: EngineApi = .init(&bc, &downloader);
    try engine_api.register(init.arena.allocator(), &authrpc_server);

    var authrpc_http = (try RpcHttpServer.init(init.io, slabs.allocator(), &authrpc_server, opts.authrpc_addr))
        .with_auth(jwt_secret);
    var authrpc_thread = try init.io.concurrent(RpcHttpServer.run, .{&authrpc_http});
    defer authrpc_thread.cancel(init.io) catch {};

    try downloader.run();
}
