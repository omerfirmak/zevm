const std = @import("std");

const Deps = struct {
    secp256k1_mod: *std.Build.Module,
    secp256k1_lib: *std.Build.Step.Compile,
    blst_mod: *std.Build.Module,
    ckzg4844_mod: *std.Build.Module,
    types_mod: *std.Build.Module,
    trusted_setup_mod: *std.Build.Module,
};

fn linkDeps(mod: *std.Build.Module, bp: *std.Build, d: Deps, committed_state_mod: *std.Build.Module) void {
    mod.addIncludePath(bp.path("mcl/include"));
    mod.addObjectFile(bp.path("mcl/lib/libmcl.a"));
    mod.addImport("zig-eth-secp256k1", d.secp256k1_mod);
    mod.linkLibrary(d.secp256k1_lib);
    mod.addImport("blst", d.blst_mod);
    mod.addImport("ckzg", d.ckzg4844_mod);
    mod.addImport("committed_state", committed_state_mod);
    mod.addImport("types", d.types_mod);
    mod.addImport("trusted_setup", d.trusted_setup_mod);
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
        .root_source_file = b.path("evm/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    linkDeps(zevm_mod, b, d, cs_mod);
    return .{ zevm_mod, cs_mod };
}

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const secp256k1_dep = b.dependency("zig_eth_secp256k1", .{ .target = target, .optimize = optimize });
    const ckzg4844_dep = b.dependency("ckzg_4844", .{ .target = target, .optimize = optimize });
    const blst_dep = b.dependency("blst", .{ .target = target, .optimize = optimize });
    const clap_dep = b.dependency("clap", .{ .target = target, .optimize = optimize });

    const types_mod = b.addModule("types", .{
        .root_source_file = b.path("evm/types.zig"),
        .target = target,
        .optimize = optimize,
    });

    // Embed trusted_setup.txt so precompile.init() doesn't need it at runtime.
    const wf = b.addWriteFiles();
    _ = wf.addCopyFile(ckzg4844_dep.path("src/trusted_setup.txt"), "trusted_setup.txt");
    const trusted_setup_mod = b.createModule(.{
        .root_source_file = wf.add("trusted_setup.zig",
            \\pub const data = @embedFile("trusted_setup.txt");
        ),
    });

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
    };

    // Exported zevm module for 3rd-party consumers.
    // Consumers override CommittedState by passing .committed_state in dependency args.
    const committed_state_path = b.option(
        std.Build.LazyPath,
        "committed_state",
        "Custom CommittedState implementation",
    ) orelse b.path("evm/empty_committed_state.zig");

    const cs_mod = b.addModule("committed_state", .{
        .root_source_file = committed_state_path,
        .target = target,
        .optimize = optimize,
    });
    cs_mod.addImport("types", types_mod);

    const zevm_mod = b.addModule("zevm", .{
        .root_source_file = b.path("evm/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    linkDeps(zevm_mod, b, deps, cs_mod);

    // Internal targets always use the empty committed state.
    const empty_cs_mod = b.createModule(.{
        .root_source_file = b.path("evm/empty_committed_state.zig"),
        .target = target,
        .optimize = optimize,
    });
    empty_cs_mod.addImport("types", types_mod);

    const test_step = b.step("test", "Run unit tests");
    const unit_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("evm/root.zig"),
            .target = target,
            .optimize = optimize,
        }),
        .use_llvm = true,
    });
    unit_tests.linkLibCpp();
    linkDeps(unit_tests.root_module, b, deps, empty_cs_mod);
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
    example.linkLibCpp();
    example.root_module.addImport("zevm", example_zevm_mod);
    example.root_module.addImport("committed_state", example_cs_mod);
    example_step.dependOn(&b.addRunArtifact(example).step);

    const bench_step = b.step("bench", "Run EVM benchmarks");
    const bench = b.addExecutable(.{
        .name = "bench",
        .root_module = b.createModule(.{
            .root_source_file = b.path("evm/bench.zig"),
            .target = target,
            .optimize = optimize,
        }),
        .use_llvm = true,
    });
    bench.linkLibCpp();
    linkDeps(bench.root_module, b, deps, empty_cs_mod);
    bench.root_module.addImport("clap", clap_dep.module("clap"));
    const run_bench = b.addRunArtifact(bench);
    if (b.args) |bench_args| run_bench.addArgs(bench_args);
    bench_step.dependOn(&run_bench.step);

    const state_test_step = b.step("state-tests", "Run EVM state tests");
    const test_zevm_mod, const test_cs_mod = createZevmModule(b, target, optimize, b.path("test/committed_state.zig"), deps);
    const state_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("test/state_tests.zig"),
            .target = target,
            .optimize = optimize,
        }),
        .use_llvm = true,
    });
    state_tests.linkLibCpp();
    state_tests.root_module.addImport("zevm", test_zevm_mod);
    state_tests.root_module.addImport("committed_state", test_cs_mod);
    state_tests.stack_size = 64 * 1024 * 1024;
    const run_state_tests = b.addRunArtifact(state_tests);
    run_state_tests.setCwd(b.path("."));
    if (b.option([]const u8, "state-test", "Path to a specific state test JSON file")) |path| {
        run_state_tests.setEnvironmentVariable("STATE_TEST", path);
    }
    state_test_step.dependOn(&run_state_tests.step);
}
