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

A `CommittedState` must be a struct exposing the same methods as the default implementation in `src/evm/committed_state.zig`. See `example/committed_state.zig` for a working consumer-side example.

## Using zevm as a dependency

Add zevm to your `build.zig.zon`:

```zig
.zevm = .{
    .url = "git+https://github.com/omerfirmak/zevm.git#<commit>",
    .hash = "<hash>",
},
```

If you only need to execute against a zero world state — no real account balances, storage, or code — wire zevm directly:

```zig
const zevm_dep = b.dependency("zevm", .{
    .target = target,
    .optimize = optimize,
});
exe.root_module.addImport("zevm", zevm_dep.module("zevm"));
```

The default `committed_state_impl = .empty` selects the built-in empty implementation: account/storage reads return zero, code lookups return `error.NotFound`.

To back zevm with a real database / in-memory map / anything else, opt into `.external` and wire your own implementation module:

```zig
const zevm_dep = b.dependency("zevm", .{
    .target = target,
    .optimize = optimize,
    .committed_state_impl = .external,
});
const zevm_mod = zevm_dep.module("zevm");

// Your CommittedState implementation. It can `@import("zevm")` to use
// `types.Account`, `types.StorageLookup`, `Trie`, etc.
const cs_mod = b.createModule(.{
    .root_source_file = b.path("src/my_committed_state.zig"),
    .target = target,
    .optimize = optimize,
});
cs_mod.addImport("zevm", zevm_mod);
zevm_mod.addImport("committed_state", cs_mod);

exe.root_module.addImport("zevm", zevm_mod);
```

The two `addImport` calls form an intentional cycle — zevm imports your committed_state, and your committed_state file gets a `"zevm"` import to use back. This lets your implementation reference zevm types without you having to redeclare them.
