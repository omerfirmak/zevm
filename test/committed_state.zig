// Copyright (c) 2025-2026 zevm authors
// SPDX-License-Identifier: MIT OR Apache-2.0

const std = @import("std");
const zevm = @import("zevm");
const types = zevm.types;

pub const Errors = error{
    NotFound,
};

pub const CommittedState = struct {
    account_map: std.AutoHashMap(u160, types.Account),
    storage_map: std.AutoHashMap(types.StorageLookup, u256),
    code_map: std.AutoHashMap([32]u8, []const u8),
    analyses: std.AutoHashMap([32]u8, zevm.Bytecode.Analysis),

    pub fn init(alloc: std.mem.Allocator) @This() {
        return .{
            .account_map = std.AutoHashMap(u160, types.Account).init(alloc),
            .storage_map = std.AutoHashMap(types.StorageLookup, u256).init(alloc),
            .code_map = std.AutoHashMap([32]u8, []const u8).init(alloc),
            .analyses = std.AutoHashMap([32]u8, zevm.Bytecode.Analysis).init(alloc),
        };
    }

    pub fn deinit(self: *@This()) void {
        var values = self.analyses.valueIterator();
        while (values.next()) |analysis| analysis.deinit(self.analyses.allocator);
        self.analyses.deinit();
        self.account_map.deinit();
        self.storage_map.deinit();
        self.code_map.deinit();
    }

    pub fn account(self: *const @This(), addr: u160) !types.Account {
        return self.account_map.get(addr) orelse .{
            .nonce = 0,
            .balance = 0,
            .code_hash = types.empty_code_hash,
            .storage_hash = types.empty_root_hash,
        };
    }

    pub fn storage(self: *const @This(), key: types.StorageLookup) !u256 {
        return self.storage_map.get(key) orelse 0;
    }

    pub fn code(self: *const @This(), hash: [32]u8) ![]const u8 {
        return self.code_map.get(hash) orelse Errors.NotFound;
    }

    /// Prepared before execution; the immutable fixture code and this map stay
    /// alive until its State and all EVM frames have finished.
    pub fn prepareCodeAnalysis(self: *@This(), comptime fork: zevm.spec.Spec) !void {
        std.debug.assert(self.analyses.count() == 0);
        var entries = self.code_map.iterator();
        while (entries.next()) |entry| {
            const analysis = try zevm.Bytecode.Analysis.init(self.analyses.allocator, entry.value_ptr.*, .{ .fork = fork });
            errdefer analysis.deinit(self.analyses.allocator);
            try self.analyses.put(entry.key_ptr.*, analysis);
        }
    }

    pub fn codeAnalysis(self: *const @This(), hash: [32]u8) ?*const zevm.Bytecode.Analysis {
        return self.analyses.getPtr(hash);
    }
};
