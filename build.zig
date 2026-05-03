const std = @import("std");

const Deps = struct {
    secp256k1_mod: *std.Build.Module,
    secp256k1_lib: *std.Build.Step.Compile,
    blst_mod: *std.Build.Module,
    ckzg4844_mod: *std.Build.Module,
    types_mod: *std.Build.Module,
    trusted_setup_mod: *std.Build.Module,
    mcl_lib: *std.Build.Step.Compile,
    mcl_include: std.Build.LazyPath,
    rlp_mod: *std.Build.Module,
};

fn linkDeps(mod: *std.Build.Module, d: Deps, committed_state_mod: *std.Build.Module) void {
    mod.addIncludePath(d.mcl_include);
    mod.linkLibrary(d.mcl_lib);
    mod.addImport("zig-eth-secp256k1", d.secp256k1_mod);
    mod.linkLibrary(d.secp256k1_lib);
    mod.addImport("blst", d.blst_mod);
    mod.addImport("ckzg", d.ckzg4844_mod);
    mod.addImport("committed_state", committed_state_mod);
    mod.addImport("types", d.types_mod);
    mod.addImport("trusted_setup", d.trusted_setup_mod);
    mod.addImport("rlp", d.rlp_mod);
}

fn buildMcl(b: *std.Build, mcl_dep: *std.Build.Dependency, target: std.Build.ResolvedTarget) *std.Build.Step.Compile {
    const lib = b.addLibrary(.{
        .name = "mcl",
        .linkage = .static,
        .root_module = b.createModule(.{
            .target = target,
            .optimize = .ReleaseFast,
        }),
        .use_llvm = true,
    });

    lib.root_module.addCSourceFiles(.{
        .root = mcl_dep.path("."),
        .files = &.{ "src/fp.cpp", "src/base64.ll", "src/bint64.ll" },
        .flags = &.{
            "-DMCL_FP_BIT=256",
            "-DMCL_FR_BIT=256",
            "-DMCL_USE_LLVM=1",
            "-DMCL_BINT_ASM=1",
            "-DMCL_BINT_ASM_X64=0",
            "-DMCL_MSM=0",
            "-DNDEBUG",
            "-DMCL_DONT_USE_XBYAK",
            "-fomit-frame-pointer",
            "-fno-stack-protector",
        },
    });
    lib.root_module.addIncludePath(mcl_dep.path("include"));
    lib.root_module.addIncludePath(mcl_dep.path("src"));
    lib.root_module.link_libcpp = true;

    return lib;
}

fn createZevmModule(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    committed_state_path: std.Build.LazyPath,
    d: Deps,
) struct { *std.Build.Module, *std.Build.Module } {
    const cs_mod = b.createModule(.{
        .root_source_file = committed_state_path,
        .target = target,
        .optimize = optimize,
    });
    cs_mod.addImport("types", d.types_mod);
    const zevm_mod = b.createModule(.{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    linkDeps(zevm_mod, d, cs_mod);
    return .{ zevm_mod, cs_mod };
}

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const secp256k1_dep = b.dependency("zig_eth_secp256k1", .{ .target = target, .optimize = optimize });
    const ckzg4844_dep = b.dependency("ckzg_4844", .{ .target = target, .optimize = optimize });
    const blst_dep = b.dependency("blst", .{ .target = target, .optimize = optimize });
    const clap_dep = b.dependency("clap", .{ .target = target, .optimize = optimize });
    const mcl_dep = b.dependency("mcl", .{});
    const rlp_dep = b.dependency("rlp", .{ .target = target, .optimize = optimize });

    const types_mod = b.addModule("types", .{
        .root_source_file = b.path("src/types/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    types_mod.addImport("rlp", rlp_dep.module("zig-rlp"));

    // Embed trusted_setup.txt so precompile.init() doesn't need it at runtime.
    const wf = b.addWriteFiles();
    _ = wf.addCopyFile(ckzg4844_dep.path("src/trusted_setup.txt"), "trusted_setup.txt");
    const trusted_setup_mod = b.createModule(.{
        .root_source_file = wf.add("trusted_setup.zig",
            \\pub const data = @embedFile("trusted_setup.txt");
        ),
    });

    const mcl_lib = buildMcl(b, mcl_dep, target);

    const deps = Deps{
        .secp256k1_mod = secp256k1_dep.module("zig-eth-secp256k1"),
        .secp256k1_lib = secp256k1_dep.artifact("secp256k1"),
        .ckzg4844_mod = ckzg4844_dep.module("ckzg"),
        .blst_mod = b.createModule(.{
            .root_source_file = blst_dep.path("bindings/zig/blst.zig"),
            .target = target,
            .optimize = optimize,
        }),
        .types_mod = types_mod,
        .trusted_setup_mod = trusted_setup_mod,
        .mcl_lib = mcl_lib,
        .mcl_include = mcl_dep.path("include"),
        .rlp_mod = rlp_dep.module("zig-rlp"),
    };

    // Exported zevm module for 3rd-party consumers.
    // Consumers override CommittedState by passing .committed_state in dependency args.
    const committed_state_path = b.option(
        std.Build.LazyPath,
        "committed_state",
        "Custom CommittedState implementation",
    ) orelse b.path("src/evm/empty_committed_state.zig");

    const cs_mod = b.addModule("committed_state", .{
        .root_source_file = committed_state_path,
        .target = target,
        .optimize = optimize,
    });
    cs_mod.addImport("types", types_mod);

    const zevm_mod = b.addModule("zevm", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    linkDeps(zevm_mod, deps, cs_mod);

    // Internal targets always use the empty committed state.
    const empty_cs_mod = b.createModule(.{
        .root_source_file = b.path("src/evm/empty_committed_state.zig"),
        .target = target,
        .optimize = optimize,
    });
    empty_cs_mod.addImport("types", types_mod);

    const test_step = b.step("test", "Run unit tests");

    const unit_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/unit_tests.zig"),
            .target = target,
            .optimize = optimize,
        }),
        .use_llvm = true,
    });
    unit_tests.root_module.link_libcpp = true;
    linkDeps(unit_tests.root_module, deps, empty_cs_mod);
    test_step.dependOn(&b.addRunArtifact(unit_tests).step);

    const example_step = b.step("example", "Run the example program");
    const example_zevm_mod, const example_cs_mod = createZevmModule(b, target, optimize, b.path("example/committed_state.zig"), deps);
    const example = b.addExecutable(.{
        .name = "example",
        .root_module = b.createModule(.{
            .root_source_file = b.path("example/main.zig"),
            .target = target,
            .optimize = optimize,
        }),
        .use_llvm = true,
    });
    example.root_module.link_libcpp = true;
    example.root_module.addImport("zevm", example_zevm_mod);
    example.root_module.addImport("committed_state", example_cs_mod);
    example_step.dependOn(&b.addRunArtifact(example).step);

    const bench_step = b.step("bench", "Run EVM benchmarks");
    const bench = b.addExecutable(.{
        .name = "bench",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/bench.zig"),
            .target = target,
            .optimize = optimize,
        }),
        .use_llvm = true,
    });
    bench.root_module.link_libcpp = true;
    linkDeps(bench.root_module, deps, empty_cs_mod);
    bench.root_module.addImport("clap", clap_dep.module("clap"));
    const run_bench = b.addRunArtifact(bench);
    if (b.args) |bench_args| run_bench.addArgs(bench_args);
    bench_step.dependOn(&run_bench.step);

    // Shared modules for all integration test binaries.
    const test_zevm_mod, const test_cs_mod = createZevmModule(b, target, optimize, b.path("test/committed_state.zig"), deps);

    const state_test_step = b.step("state-tests", "Run EVM state tests");
    const state_tests = b.addTest(.{
        .name = "zevm-state-test",
        .root_module = b.createModule(.{
            .root_source_file = b.path("test/state_tests.zig"),
            .target = target,
            .optimize = optimize,
        }),
        .use_llvm = true,
    });
    state_tests.root_module.link_libcpp = true;
    state_tests.root_module.addImport("zevm", test_zevm_mod);
    state_tests.root_module.addImport("committed_state", test_cs_mod);
    state_tests.stack_size = 64 * 1024 * 1024;
    b.installArtifact(state_tests);
    const run_state_tests = b.addRunArtifact(state_tests);
    run_state_tests.setCwd(b.path("."));
    if (b.option([]const u8, "state-test", "Path to a specific state test JSON file")) |path| {
        run_state_tests.setEnvironmentVariable("STATE_TEST", path);
    }
    if (b.option(bool, "trace", "Enable tracing")) |_| {
        run_state_tests.setEnvironmentVariable("TRACE", "TRUE");
    }
    const fork_option = b.option([]const u8, "fork", "Fork");
    if (fork_option) |f| {
        run_state_tests.setEnvironmentVariable("FORK", f);
    }
    state_test_step.dependOn(&run_state_tests.step);

    const blockchain_test_step = b.step("blockchain-tests", "Run EVM blockchain tests");
    const blockchain_tests = b.addTest(.{
        .name = "zevm-blockchain-test",
        .root_module = b.createModule(.{
            .root_source_file = b.path("test/blockchain_tests.zig"),
            .target = target,
            .optimize = optimize,
        }),
        .use_llvm = true,
    });
    blockchain_tests.root_module.link_libcpp = true;
    blockchain_tests.root_module.addImport("zevm", test_zevm_mod);
    blockchain_tests.root_module.addImport("committed_state", test_cs_mod);
    blockchain_tests.root_module.addImport("rlp", rlp_dep.module("zig-rlp"));
    blockchain_tests.stack_size = 64 * 1024 * 1024;
    const run_blockchain_tests = b.addRunArtifact(blockchain_tests);
    run_blockchain_tests.setCwd(b.path("."));
    if (b.option([]const u8, "blockchain-test", "Path to a specific blockchain test JSON file")) |path| {
        run_blockchain_tests.setEnvironmentVariable("BLOCKCHAIN_TEST", path);
    }
    if (fork_option) |f| {
        run_blockchain_tests.setEnvironmentVariable("FORK", f);
    }
    blockchain_test_step.dependOn(&run_blockchain_tests.step);
}
