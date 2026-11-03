// Copyright (c) 2025-2026 zevm authors
// SPDX-License-Identifier: MIT OR Apache-2.0

const std = @import("std");
const RpcServer = @import("jsonrpc.zig").Server;
const Blockchain = @import("../node/blockchain.zig").Blockchain;
const Downloader = @import("../node/downloader.zig").Downloader;
const backend = @import("../node/engine.zig");
const types = @import("../types.zig");
pub const hex = @import("hex.zig");

pub const Engine = struct {
    const Self = @This();

    bc: *Blockchain,
    downloader: *Downloader,

    pub fn init(bc: *Blockchain, downloader: *Downloader) Self {
        return .{ .bc = bc, .downloader = downloader };
    }

    pub fn register(self: *Self, allocator: std.mem.Allocator, server: *RpcServer) !void {
        try server.register(allocator, "engine_exchangeCapabilities", @ptrCast(self), Engine.exchangeCapabilities);
    }

    pub fn exchangeCapabilities(_: *Self, _: std.Io, _: std.mem.Allocator) ![]const []const u8 {
        return &[_][]const u8{};
    }
};

pub const WithdrawalV1 = struct {
    index: hex.Number(u64),
    validatorIndex: hex.Number(u64),
    address: hex.Data(20),
    amount: hex.Number(u64),
};

pub const ExecutionPayload = struct {
    parentHash: hex.Data(32),
    feeRecipient: hex.Data(20),
    stateRoot: hex.Data(32),
    receiptsRoot: hex.Data(32),
    logsBloom: hex.Data(256),
    prevRandao: hex.Data(32),
    blockNumber: hex.Number(u64),
    gasLimit: hex.Number(u64),
    gasUsed: hex.Number(u64),
    timestamp: hex.Number(u64),
    extraData: hex.Bytes,
    baseFeePerGas: hex.Number(u256),
    blockHash: hex.Data(32),
    transactions: []const hex.Bytes,
    withdrawals: []const WithdrawalV1,
    blobGasUsed: hex.Number(u64),
    excessBlobGas: hex.Number(u64),
    blockAccessList: hex.Bytes,
    slotNumber: hex.Number(u64),

    pub fn toExecutionPayload(self: *const ExecutionPayload, allocator: std.mem.Allocator) !backend.ExecutionPayload {
        const txs = try allocator.alloc([]const u8, self.transactions.len);
        errdefer allocator.free(txs);
        for (self.transactions, txs) |src, *dst| dst.* = src.bytes;

        const withdrawals = try allocator.alloc(types.Withdrawal, self.withdrawals.len);
        for (self.withdrawals, withdrawals) |src, *dst| dst.* = .{
            .index = src.index.number,
            .validator_index = src.validatorIndex.number,
            .address = src.address.bytes,
            .amount = src.amount.number,
        };

        return .{
            .parent_hash = self.parentHash.bytes,
            .fee_recipient = self.feeRecipient.bytes,
            .state_root = self.stateRoot.bytes,
            .receipts_root = self.receiptsRoot.bytes,
            .logs_bloom = self.logsBloom.bytes,
            .prev_randao = self.prevRandao.bytes,
            .block_number = self.blockNumber.number,
            .gas_limit = self.gasLimit.number,
            .gas_used = self.gasUsed.number,
            .timestamp = self.timestamp.number,
            .extra_data = self.extraData.bytes,
            .base_fee_per_gas = self.baseFeePerGas.number,
            .block_hash = self.blockHash.bytes,
            .transactions = txs,
            .withdrawals = withdrawals,
            .blob_gas_used = self.blobGasUsed.number,
            .excess_blob_gas = self.excessBlobGas.number,
            .block_access_list = self.blockAccessList.bytes,
            .slot_number = self.slotNumber.number,
        };
    }
};
