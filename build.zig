const std = @import("std");

const Deps = struct {
    secp256k1_mod: *std.Build.Module,
    secp256k1_lib: *std.Build.Step.Compile,
    blst_mod: *std.Build.Module,
    ckzg4844_mod: *std.Build.Module,
    trusted_setup_mod: *std.Build.Module,
    mcl_lib: *std.Build.Step.Compile,
    mcl_mod: *std.Build.Module,
    zkvm_mod: *std.Build.Module,
    rlp_mod: *std.Build.Module,
};

fn linkDeps(mod: *std.Build.Module, d: Deps, platform: Platform) void {
    mod.addImport("rlp", d.rlp_mod);
    switch (platform) {
        .native => {
            mod.linkLibrary(d.mcl_lib);
            mod.addImport("mcl", d.mcl_mod);
            mod.linkLibrary(d.secp256k1_lib);
            mod.addImport("zig-eth-secp256k1", d.secp256k1_mod);
            mod.addImport("blst", d.blst_mod);
            mod.addImport("ckzg", d.ckzg4844_mod);
            mod.addImport("trusted_setup", d.trusted_setup_mod);
        },
        .zkvm => {
            mod.addImport("zkvm", d.zkvm_mod);
        },
    }
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

    const is_64 = target.result.ptrBitWidth() == 64;
    const base_ll = if (is_64) "src/base64.ll" else "src/base32.ll";
    const bint_ll = if (is_64) "src/bint64.ll" else "src/bint32.ll";

    lib.root_module.addCSourceFiles(.{
        .root = mcl_dep.path("."),
        .files = &.{ "src/fp.cpp", base_ll, bint_ll },
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
    committed_state_mod: ?*std.Build.Module,
    platform: Platform,
    d: Deps,
) *std.Build.Module {
    const options = b.addOptions();
    options.addOption(State, "state", if (committed_state_mod != null) .external else .empty);
    options.addOption(Platform, "platform", platform);

    const zevm_mod = b.createModule(.{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    zevm_mod.addOptions("build_options", options);
    linkDeps(zevm_mod, d, platform);
    if (committed_state_mod) |cs_mod| {
        cs_mod.addImport("zevm", zevm_mod);
        zevm_mod.addImport("committed_state", cs_mod);
    }
    return zevm_mod;
}

pub const State = enum {
    empty,
    external,
};

pub const Platform = enum {
    native,
    zkvm,
};

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const secp256k1_dep = b.dependency("zig_eth_secp256k1", .{ .target = target, .optimize = optimize });
    const ckzg4844_dep = b.dependency("ckzg_4844", .{ .target = target, .optimize = optimize });
    const blst_dep = b.dependency("blst", .{ .target = target, .optimize = optimize });
    const clap_dep = b.dependency("clap", .{ .target = target, .optimize = optimize });
    const mcl_dep = b.dependency("mcl", .{});
    const rlp_dep = b.dependency("rlp", .{ .target = target, .optimize = optimize });
    const ssz_dep = b.dependency("ssz", .{ .target = target, .optimize = optimize });
    const zisk_dep = b.dependency("zisk", .{});

    const mcl_lib = buildMcl(b, mcl_dep, target);
    const mcl = b.addTranslateC(.{
        .root_source_file = mcl_dep.path("include/mcl/bn_c256.h"),
        .target = target,
        .optimize = optimize,
    });
    mcl.addIncludePath(mcl_dep.path("include"));

    const zkvm = b.addTranslateC(.{
        .root_source_file = b.path("zkvm/zkvm.h"),
        .target = target,
        .optimize = optimize,
        .link_libc = false,
    });
    zkvm.addIncludePath(zisk_dep.path("zkvm-interface"));

    const deps = Deps{
        .secp256k1_mod = secp256k1_dep.module("zig-eth-secp256k1"),
        .secp256k1_lib = secp256k1_dep.artifact("secp256k1"),
        .ckzg4844_mod = ckzg4844_dep.module("ckzg"),
        .blst_mod = b.createModule(.{
            .root_source_file = blst_dep.path("bindings/zig/blst.zig"),
            .target = target,
            .optimize = optimize,
        }),
        .trusted_setup_mod = ckzg4844_dep.module("trusted_setup"),
        .mcl_lib = mcl_lib,
        .mcl_mod = mcl.createModule(),
        .zkvm_mod = zkvm.createModule(),
        .rlp_mod = rlp_dep.module("zig-rlp"),
    };

    // Public surface
    const options = b.addOptions();
    options.addOption(State, "state", b.option(
        State,
        "committed_state",
        "Custom CommittedState implementation enabler",
    ) orelse .empty);
    const public_platform: Platform = b.option(
        Platform,
        "platform",
        "Platform selector",
    ) orelse .native;
    options.addOption(Platform, "platform", public_platform);
    const zevm_mod = b.addModule("zevm", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    linkDeps(zevm_mod, deps, public_platform);
    zevm_mod.addOptions("build_options", options);

    // Tests
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
    const native_opts = b.addOptions();
    native_opts.addOption(State, "state", .empty);
    native_opts.addOption(Platform, "platform", .native);
    unit_tests.root_module.addOptions("build_options", native_opts);
    linkDeps(unit_tests.root_module, deps, .native);
    test_step.dependOn(&b.addRunArtifact(unit_tests).step);

    // Example user
    const example_step = b.step("example", "Run the example program");
    const example_zevm_mod = createZevmModule(
        b,
        target,
        optimize,
        b.createModule(.{
            .root_source_file = b.path("example/committed_state.zig"),
            .target = target,
            .optimize = optimize,
        }),
        .native,
        deps,
    );
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
    example_step.dependOn(&b.addRunArtifact(example).step);

    // Benchmark
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
    linkDeps(bench.root_module, deps, .native);
    bench.root_module.addImport("clap", clap_dep.module("clap"));
    const run_bench = b.addRunArtifact(bench);
    if (b.args) |bench_args| run_bench.addArgs(bench_args);
    bench_step.dependOn(&run_bench.step);

    const test_zevm_mod = createZevmModule(b, target, optimize, b.createModule(.{
        .root_source_file = b.path("test/committed_state.zig"),
        .target = target,
        .optimize = optimize,
    }), .native, deps);

    // State tests
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
    state_tests.root_module.addImport("rlp", rlp_dep.module("zig-rlp"));
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

    // Blockchain tests
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
    blockchain_tests.root_module.addImport("rlp", rlp_dep.module("zig-rlp"));
    blockchain_tests.stack_size = 64 * 1024 * 1024;
    b.installArtifact(blockchain_tests);
    const run_blockchain_tests = b.addRunArtifact(blockchain_tests);
    run_blockchain_tests.setCwd(b.path("."));
    if (b.option([]const u8, "blockchain-test", "Path to a specific blockchain test JSON file")) |path| {
        run_blockchain_tests.setEnvironmentVariable("BLOCKCHAIN_TEST", path);
    }
    if (fork_option) |f| {
        run_blockchain_tests.setEnvironmentVariable("FORK", f);
    }
    blockchain_test_step.dependOn(&run_blockchain_tests.step);

    // zkEVM tests
    const stateless_cs_mod = b.createModule(.{
        .root_source_file = b.path("src/stateless/committed_state.zig"),
        .target = target,
        .optimize = optimize,
    });
    stateless_cs_mod.addImport("ssz", ssz_dep.module("ssz.zig"));
    stateless_cs_mod.addImport("rlp", rlp_dep.module("zig-rlp"));
    const stateless_zevm_mod = createZevmModule(b, target, optimize, stateless_cs_mod, .native, deps);
    const guest_mod = b.createModule(.{
        .root_source_file = b.path("src/stateless/guest.zig"),
        .target = target,
        .optimize = optimize,
    });
    guest_mod.addImport("zevm", stateless_zevm_mod);
    guest_mod.addImport("committed_state", stateless_cs_mod);
    guest_mod.addImport("rlp", rlp_dep.module("zig-rlp"));
    guest_mod.addImport("ssz", ssz_dep.module("ssz.zig"));

    const zkevm_test_step = b.step("zk-tests", "Run zkEVM blockchain tests");
    const zkevm_tests = b.addTest(.{
        .name = "zevm-zkevm-test",
        .root_module = b.createModule(.{
            .root_source_file = b.path("test/zkevm_tests.zig"),
            .target = target,
            .optimize = optimize,
        }),
        .use_llvm = true,
    });
    zkevm_tests.root_module.link_libcpp = true;
    zkevm_tests.root_module.addImport("guest", guest_mod);
    zkevm_tests.stack_size = 64 * 1024 * 1024;
    b.installArtifact(zkevm_tests);
    const run_zkevm_tests = b.addRunArtifact(zkevm_tests);
    run_zkevm_tests.setCwd(b.path("."));
    if (b.option([]const u8, "zk-test", "Path to a specific zkEVM blockchain test JSON file")) |path| {
        run_zkevm_tests.setEnvironmentVariable("ZK_TEST", path);
    }
    if (fork_option) |f| {
        run_zkevm_tests.setEnvironmentVariable("FORK", f);
    }
    zkevm_test_step.dependOn(&run_zkevm_tests.step);

    // Zisk
    const ziskos_step = b.step("ziskos", "Build libziskos_staticlib.a via cargo +zisk");
    const ziskos_build = b.addSystemCommand(&.{
        "cargo",
        "+zisk",
        "build",
        "-p",
        "ziskos-staticlib",
        "--release",
        "--target",
        "riscv64ima-zisk-zkvm-elf",
        "--config",
        "profile.release.lto=\"fat\"",
    });
    ziskos_build.setCwd(zisk_dep.path(""));
    ziskos_build.setEnvironmentVariable("CARGO_TARGET_DIR", b.pathFromRoot(".zig-cache/ziskos-cargo-target"));
    ziskos_step.dependOn(&ziskos_build.step);

    const guest_target = b.resolveTargetQuery(.{
        .cpu_arch = .riscv64,
        .cpu_model = .{ .explicit = &std.Target.riscv.cpu.baseline_rv64 },
        .cpu_features_add = std.Target.riscv.featureSet(&.{ .m, .zicclsm }),
        .cpu_features_sub = std.Target.riscv.featureSet(&.{ .c, .d, .f, .zicsr }),
        .os_tag = .freestanding,
        .abi = .none,
    });
    const guest_cs_mod = b.createModule(.{
        .root_source_file = b.path("src/stateless/committed_state.zig"),
        .target = guest_target,
        .optimize = optimize,
        .link_libc = false,
        .single_threaded = true,
    });
    guest_cs_mod.addImport("ssz", ssz_dep.module("ssz.zig"));
    guest_cs_mod.addImport("rlp", rlp_dep.module("zig-rlp"));
    const guest_zkvm_zevm_mod = createZevmModule(b, guest_target, optimize, guest_cs_mod, .zkvm, deps);
    guest_zkvm_zevm_mod.link_libc = false;
    guest_zkvm_zevm_mod.single_threaded = true;
    const guest_lib_mod = b.createModule(.{
        .root_source_file = b.path("src/stateless/main.zig"),
        .target = guest_target,
        .optimize = optimize,
        .link_libc = false,
        .single_threaded = true,
    });
    guest_lib_mod.addImport("zkvm", deps.zkvm_mod);
    guest_lib_mod.addAnonymousImport("guest.zig", .{
        .root_source_file = b.path("src/stateless/guest.zig"),
        .target = guest_target,
        .optimize = optimize,
        .single_threaded = true,
        .imports = &.{
            .{ .name = "zevm", .module = guest_zkvm_zevm_mod },
            .{ .name = "committed_state", .module = guest_cs_mod },
            .{ .name = "rlp", .module = rlp_dep.module("zig-rlp") },
            .{ .name = "ssz", .module = ssz_dep.module("ssz.zig") },
        },
    });

    const zisk_exe = b.addExecutable(.{
        .name = "zevm-zisk-guest",
        .root_module = guest_lib_mod,
        .use_llvm = true,
    });
    zisk_exe.entry = .disabled;
    zisk_exe.root_module.link_libc = false;
    zisk_exe.root_module.code_model = .medium;
    zisk_exe.setLinkerScript(b.path("zkvm/zisk/link.ld"));
    zisk_exe.root_module.addObjectFile(b.path(".zig-cache/ziskos-cargo-target/riscv64ima-zisk-zkvm-elf/release/libziskos_staticlib.a"));
    zisk_exe.step.dependOn(&ziskos_build.step);
    const guest_step = b.step("zisk", "Build src/stateless/main.zig as the zisk guest executable");
    guest_step.dependOn(&b.addInstallArtifact(zisk_exe, .{}).step);
}
