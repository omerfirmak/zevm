const std = @import("std");
const evm = @import("evm.zig");
const state_mod = @import("state.zig");
const ops = @import("ops.zig");
const spec = @import("spec.zig");

pub fn main() !void {
    var gpa_state = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa_state.deinit();
    const allocator = gpa_state.allocator();

    // Choose a fork and build the jump table for it.
    const fork = spec.Osaka;
    const jump_table = ops.Ops(fork).table();

    // Set up world state with enough capacity for this example.
    var state = try state_mod.State.init(allocator, 100_000);
    defer state.deinit(allocator);

    // Fund the sender.
    const sender: u160 = 0xdeadbeef;
    _ = state.accounts.write(sender, .{
        .nonce = 0,
        .balance = 1_000_000_000_000_000_000, // 1 ETH
        .code_hash = state_mod.empty_code_hash,
        .storage_hash = state_mod.empty_root_hash,
    });

    // Deploy a contract: PUSH1 0x2a  PUSH1 0x00  MSTORE  PUSH1 0x20  PUSH1 0x00  RETURN
    // This stores 42 in memory and returns 32 bytes containing it.
    const bytecode = [_]u8{ 0x60, 0x2a, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3 };
    var code_hash_bytes: [32]u8 = undefined;
    std.crypto.hash.sha3.Keccak256.hash(&bytecode, &code_hash_bytes, .{});
    const code_hash = std.mem.readInt(u256, &code_hash_bytes, .big);
    state.deploy_code(code_hash, &bytecode, @ptrCast(&jump_table));

    const contract: u160 = 0xcafe;
    _ = state.accounts.write(contract, .{
        .nonce = 1,
        .balance = 0,
        .code_hash = code_hash,
        .storage_hash = state_mod.empty_root_hash,
    });

    // Describe the block.
    const context = evm.Context{
        .chainid = 1,
        .number = 1,
        .coinbase = 0,
        .time = 1000,
        .random = 0,
        .basefee = 7,
        .gas_limit = 30_000_000,
        .excess_blob_gas = 0,
        .max_blobs_per_block = 9,
        .blob_base_fee_update_fraction = 5_000_000,
    };

    // Describe the transaction (legacy, CALL).
    var calldata = [_]u8{};
    const msg = evm.Message{
        .caller = sender,
        .nonce = 0,
        .target = contract,
        .gas_limit = 100_000,
        .gas_price = 7,
        .calldata = &calldata,
        .value = 0,
    };

    // Use an arena for the EVM's internal buffers (return buffer, warm sets, etc.);
    // freeing the arena at the end reclaims everything at once.
    var vm_arena = std.heap.ArenaAllocator.init(allocator);
    defer vm_arena.deinit();
    const vm_alloc = vm_arena.allocator();

    var logs: std.DoublyLinkedList = .{};
    var vm = try evm.EVM.init(vm_alloc, vm_alloc, &logs, &msg, &context, @ptrCast(&jump_table));

    // process() returns an error only for invalid transactions (bad nonce, insufficient
    // funds, etc.). Reverts are NOT errors — check return data for revert payloads.
    vm.process(fork, &state) catch |err| {
        std.debug.print("transaction invalid: {}\n", .{err});
        return;
    };

    const result = vm.return_buffer[0..vm.return_data_size];
    const value = if (result.len >= 32) std.mem.readInt(u256, result[0..32], .big) else 0;
    std.debug.print("return data ({d} bytes): 0x", .{result.len});
    for (result) |b| std.debug.print("{x:0>2}", .{b});
    std.debug.print("\ndecoded u256: {d}\n", .{value});
}
