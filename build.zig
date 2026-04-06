const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const secp256k1_dep = b.dependency("zig_eth_secp256k1", .{ .target = target, .optimize = optimize });
    const secp256k1_mod = secp256k1_dep.module("zig-eth-secp256k1");
    const secp256k1_lib = secp256k1_dep.artifact("secp256k1");

    const ckzg4844_dep = b.dependency("ckzg_4844", .{ .target = target, .optimize = optimize });
    const ckzg4844_mod = ckzg4844_dep.module("ckzg");
    const ckzg4844_lib = ckzg4844_dep.artifact("ckzg");

    const blst_dep = b.dependency("blst", .{ .target = target, .optimize = optimize });
    const blst_mod = b.createModule(.{
        .root_source_file = blst_dep.path("bindings/zig/blst.zig"),
        .target = target,
        .optimize = optimize,
    });
    const blst_lib = b.addLibrary(.{
        .name = "blst",
        .linkage = .static,
        .root_module = blst_mod,
    });

    const zevm_mod = b.addModule("zevm", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    zevm_mod.addIncludePath(b.path("mcl/include"));
    zevm_mod.addObjectFile(b.path("mcl/lib/libmcl.a"));
    zevm_mod.addImport("zig-eth-secp256k1", secp256k1_mod);
    zevm_mod.linkLibrary(secp256k1_lib);
    zevm_mod.addImport("blst", blst_mod);
    zevm_mod.linkLibrary(blst_lib);
    zevm_mod.addImport("ckzg", ckzg4844_mod);
    zevm_mod.linkLibrary(ckzg4844_lib);

    const test_step = b.step("test", "Run unit tests");
    const unit_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/root.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    unit_tests.linkLibCpp();
    unit_tests.root_module.addIncludePath(b.path("mcl/include"));
    unit_tests.root_module.addObjectFile(b.path("mcl/lib/libmcl.a"));
    unit_tests.root_module.addImport("zig-eth-secp256k1", secp256k1_mod);
    unit_tests.root_module.linkLibrary(secp256k1_lib);
    unit_tests.root_module.addImport("blst", blst_mod);
    unit_tests.root_module.linkLibrary(blst_lib);
    unit_tests.root_module.addImport("ckzg", ckzg4844_mod);
    unit_tests.root_module.linkLibrary(ckzg4844_lib);
    test_step.dependOn(&b.addRunArtifact(unit_tests).step);

    const example_step = b.step("example", "Run the example program");
    const example = b.addExecutable(.{
        .name = "example",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/example.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    example.linkLibCpp();
    example.root_module.addIncludePath(b.path("mcl/include"));
    example.root_module.addObjectFile(b.path("mcl/lib/libmcl.a"));
    example.root_module.addImport("zig-eth-secp256k1", secp256k1_mod);
    example.root_module.linkLibrary(secp256k1_lib);
    example.root_module.addImport("blst", blst_mod);
    example.root_module.linkLibrary(blst_lib);
    example.root_module.addImport("ckzg", ckzg4844_mod);
    example.root_module.linkLibrary(ckzg4844_lib);
    example_step.dependOn(&b.addRunArtifact(example).step);

    const state_test_step = b.step("state-tests", "Run EVM state tests");
    const state_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/state_tests.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    state_tests.linkLibCpp();
    state_tests.root_module.addIncludePath(b.path("mcl/include"));
    state_tests.root_module.addObjectFile(b.path("mcl/lib/libmcl.a"));
    state_tests.root_module.addImport("zig-eth-secp256k1", secp256k1_mod);
    state_tests.root_module.linkLibrary(secp256k1_lib);
    state_tests.root_module.addImport("blst", blst_mod);
    state_tests.root_module.linkLibrary(blst_lib);
    state_tests.root_module.addImport("ckzg", ckzg4844_mod);
    state_tests.root_module.linkLibrary(ckzg4844_lib);
    state_tests.stack_size = 64 * 1024 * 1024;
    const run_state_tests = b.addRunArtifact(state_tests);
    run_state_tests.setCwd(b.path("."));
    if (b.option([]const u8, "state-test", "Path to a specific state test JSON file")) |path| {
        run_state_tests.setEnvironmentVariable("STATE_TEST", path);
    }
    state_test_step.dependOn(&run_state_tests.step);
}
