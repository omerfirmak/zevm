# zevm

An alpha EVM implementation in Zig, using threaded code dispatch for opcode execution. Osaka-compliant.

## Requirements

- Zig 0.15.2

## Building

```sh
zig build
```

## Running tests

Run unit tests:

```sh
zig build test
```

Run the full state test suite after fetching the fixture archive and extracting it:

```sh
zig build state-tests
```

Run a single fixture file:

```sh
zig build state-tests -Dstate-test=/path/to/fixture.json
```

## Usage

The entry point for executing a transaction is `EVM.init` followed by `EVM.process`. You need to provide a `Message` (transaction parameters), a `Context` (block parameters), and a `State` (account/storage world state).

See `example/main.zig` for a working end-to-end example (`zig build example` to run it).

## CommittedState

The EVM reads account balances, storage slots, and contract code through a `CommittedState` interface. Consumers provide their own implementation to back these reads with a real database, in-memory map, or anything else.

A `CommittedState` must be a struct exposing the same methods as the default implementation (`evm/empty_committed_state.zig`). See `example/committed_state.zig` for a working example.

## Using zevm as a dependency

zevm relies on git submodules (`c-kzg-4844`, `mcl`) that `zig fetch` does not clone. You have two options:

1. **Git submodule** — add zevm as a submodule in your project and reference it with a local path:

   ```sh
   git submodule add https://github.com/omerfirmak/zevm.git deps/zevm
   git submodule update --init --recursive
   ```

   Then in `build.zig.zon`:

   ```zig
   .zevm = .{ .path = "deps/zevm" },
   ```

2. **Vendor** — clone the repo with `--recursive`, copy it into your project tree, and reference it the same way.

Then in your `build.zig`, pass your custom `CommittedState` source file when declaring the dependency:

```zig
const zevm_dep = b.dependency("zevm", .{
    .target = target,
    .optimize = optimize,
    .committed_state = b.path("src/my_committed_state.zig"),
});

exe.root_module.addImport("zevm", zevm_dep.module("zevm"));
```

If you omit `.committed_state`, the built-in empty implementation is used (returns zeros for everything).
