# zevm

An alpha EVM implementation in Zig, using threaded code dispatch for opcode execution. Osaka-compliant.

## Requirements

- Zig 0.16.0

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

Add zevm to your `build.zig.zon`:

```zig
.zevm = .{
    .url = "git+https://github.com/omerfirmak/zevm.git#<commit>",
    .hash = "<hash>",
},
```

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
