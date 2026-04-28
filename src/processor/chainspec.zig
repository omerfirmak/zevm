const Fork = @import("../forks.zig").Fork;

pub const ChainSpec = struct {
    fork: Fork,
    chain_id: u64,

    base_fee_max_change_denominator: u64,
    base_fee_elasticity_multiplier: u64,
    gas_limit_adjustment_factor: u64,
    min_gas_limit: u64,

    max_rlp_size: u64,

    blobs_base_cost: u64,
    target_blobs_per_block: u64,
    max_blobs_per_block: u64,
    blob_base_fee_update_fraction: u64,
};

pub const Osaka: ChainSpec = .{
    .fork = .Osaka,
    .chain_id = 1,
    .base_fee_elasticity_multiplier = 2,
    .base_fee_max_change_denominator = 8,
    .gas_limit_adjustment_factor = 1024,
    .min_gas_limit = 5000,
    .max_rlp_size = 8_388_608,
    .blobs_base_cost = 1 << 13,
    .blob_base_fee_update_fraction = 5007716,
    .target_blobs_per_block = 6,
    .max_blobs_per_block = 9,
};
