# zevm

An alpha EVM implementation in Zig, using threaded code dispatch for opcode execution. Osaka-compliant.

## Requirements

- Zig 0.15.2

## Building

```sh
zig build
```

## Running tests

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

## Usage

Add zevm as a dependency in your `build.zig.zon`, then import the `evm` module from `src/root.zig`.

The entry point for executing a transaction is `EVM.init` followed by `EVM.process`. You need to provide a `Message` (transaction parameters), a `Context` (block parameters), and a `State` (account/storage world state).

See `src/example.zig` for a working end-to-end example (`zig build example` to run it). The example deploys a contract that stores a value, emits a log, and returns it — demonstrating CALL execution, log collection, and return data handling.

### Key types

| Type | Purpose |
|------|---------|
| `evm.Message` | Transaction parameters: caller, target, calldata, value, gas, access list, blob hashes, authorization list |
| `evm.Context` | Block parameters: number, coinbase, basefee, chainid, blob gas, etc. |
| `evm.EVM` | Executor. Call `init` then `process` to run a transaction. |
| `evm.Log` | Emitted log entry: address, topics, data. Collected in a `std.DoublyLinkedList` passed to `EVM.init`. |
| `state.State` | World state: accounts, contract storage, transient storage, deployed code. |
| `spec.Osaka` | Fork specification with gas constants and opcode table. |

`Message.target = null` triggers a CREATE transaction. `Message.authorization_list` (non-null) marks the transaction as EIP-7702 type-4. `Message.max_fee_per_blob_gas` (non-null) marks it as EIP-4844 type-3.

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
| `src/state_tests.zig` | Ethereum state test runner |
