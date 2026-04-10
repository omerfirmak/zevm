const std = @import("std");

const Deps = struct {
    secp256k1_mod: *std.Build.Module,
    secp256k1_lib: *std.Build.Step.Compile,
    blst_mod: *std.Build.Module,
    ckzg4844_mod: *std.Build.Module,
};

fn linkDeps(mod: *std.Build.Module, bp: *std.Build, d: Deps) void {
    mod.addIncludePath(bp.path("mcl/include"));
    mod.addObjectFile(bp.path("mcl/lib/libmcl.a"));
    mod.addImport("zig-eth-secp256k1", d.secp256k1_mod);
    mod.linkLibrary(d.secp256k1_lib);
    mod.addImport("blst", d.blst_mod);
    mod.addImport("ckzg", d.ckzg4844_mod);
}

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const secp256k1_dep = b.dependency("zig_eth_secp256k1", .{ .target = target, .optimize = optimize });
    const ckzg4844_dep = b.dependency("ckzg_4844", .{ .target = target, .optimize = optimize });
    const blst_dep = b.dependency("blst", .{ .target = target, .optimize = optimize });
    const clap_dep = b.dependency("clap", .{ .target = target, .optimize = optimize });

    const secp256k1_mod = secp256k1_dep.module("zig-eth-secp256k1");
    const secp256k1_lib = secp256k1_dep.artifact("secp256k1");
    const ckzg4844_mod = ckzg4844_dep.module("ckzg");
    const blst_mod = b.createModule(.{
        .root_source_file = blst_dep.path("bindings/zig/blst.zig"),
        .target = target,
        .optimize = optimize,
    });

    const deps = Deps{
        .secp256k1_mod = secp256k1_mod,
        .secp256k1_lib = secp256k1_lib,
        .blst_mod = blst_mod,
        .ckzg4844_mod = ckzg4844_mod,
    };

    const zevm_mod = b.addModule("zevm", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    linkDeps(zevm_mod, b, deps);

    const test_step = b.step("test", "Run unit tests");
    const unit_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/root.zig"),
            .target = target,
            .optimize = optimize,
        }),
        .use_llvm = true,
    });
    unit_tests.linkLibCpp();
    linkDeps(unit_tests.root_module, b, deps);
    test_step.dependOn(&b.addRunArtifact(unit_tests).step);

    const example_step = b.step("example", "Run the example program");
    const example = b.addExecutable(.{
        .name = "example",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/example.zig"),
            .target = target,
            .optimize = optimize,
        }),
        .use_llvm = true,
    });
    example.linkLibCpp();
    linkDeps(example.root_module, b, deps);
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
    bench.linkLibCpp();
    linkDeps(bench.root_module, b, deps);
    bench.root_module.addImport("clap", clap_dep.module("clap"));
    const run_bench = b.addRunArtifact(bench);
    if (b.args) |bench_args| run_bench.addArgs(bench_args);
    bench_step.dependOn(&run_bench.step);

    const state_test_step = b.step("state-tests", "Run EVM state tests");
    const state_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/state_tests.zig"),
            .target = target,
            .optimize = optimize,
        }),
        .use_llvm = true,
    });
    state_tests.linkLibCpp();
    linkDeps(state_tests.root_module, b, deps);
    state_tests.stack_size = 64 * 1024 * 1024;
    const run_state_tests = b.addRunArtifact(state_tests);
    run_state_tests.setCwd(b.path("."));
    if (b.option([]const u8, "state-test", "Path to a specific state test JSON file")) |path| {
        run_state_tests.setEnvironmentVariable("STATE_TEST", path);
    }
    state_test_step.dependOn(&run_state_tests.step);
}
