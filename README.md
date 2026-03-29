# zevm

A work-in-progress EVM implementation in Zig, using threaded code dispatch for opcode execution.

## Requirements

- Zig 0.15.2

## Building

```sh
zig build
```

## Running state tests

Fetch the fixture archive and extract it:

```sh
tar -xzf fixtures_develop.tar.gz
```

Run unit tests:

```sh
zig build test
```

Run the full state test suite:

```sh
zig build state-tests
```

Run a single fixture file:

```sh
zig build state-tests -Dstate-test=/path/to/fixture.json
```

## Architecture

| File | Description |
|------|-------------|
| `src/evm.zig` | `EVM` and `Frame` — entry point for calls, stack and memory |
| `src/ops.zig` | Opcode handlers and jump table, parameterised by `Spec` |
| `src/bytecode.zig` | `Bytecode` — raw bytes + threaded code + jump dest analysis |
| `src/memory.zig` | Growable EVM memory with gas metering |
| `src/state.zig` | `State` — accounts, contract storage, transient storage, code |
| `src/storage.zig` | Journaled hash-map storage with snapshot/revert |
| `src/spec.zig` | Fork specifications (currently Osaka) |
| `src/opcode.zig` | Opcode enum |
| `src/state_tests.zig` | Ethereum state test runner |
