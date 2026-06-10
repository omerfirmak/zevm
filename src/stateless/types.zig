const std = @import("std");
const List = @import("ssz").utils.List;

const MAX_EXTRA_DATA_BYTES = 32;
const MAX_BYTES_PER_TRANSACTION = 1 << 30;
const MAX_TRANSACTIONS_PER_PAYLOAD = 1 << 20;
const MAX_WITHDRAWALS_PER_PAYLOAD = 1 << 4;
const MAX_BLOB_COMMITMENTS_PER_BLOCK = 4096;
const MAX_DEPOSIT_REQUESTS_PER_PAYLOAD = 1 << 13;
const MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD = 1 << 4;
const MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD = 1 << 1;
const MAX_BLOCK_ACCESS_LIST_BYTES = 1 << 24;
const MAX_WITNESS_NODES = 1 << 20;
const MAX_WITNESS_CODES = 1 << 16;
const MAX_WITNESS_HEADERS = 256;
const MAX_BYTES_PER_WITNESS_NODE = 1 << 20;
const MAX_BYTES_PER_CODE = 1 << 24;
const MAX_BYTES_PER_HEADER = 1 << 10;
const MAX_OPTIONAL_FORK_ACTIVATION_VALUES = 1;
const MAX_BLOB_SCHEDULES_PER_FORK = 1;
const MAX_PUBLIC_KEYS = 1 << 20;

pub const Withdrawal = struct {
    index: u64,
    validator_index: u64,
    address: [20]u8,
    amount: u64,
};

pub const ExecutionPayload = struct {
    parent_hash: [32]u8,
    fee_recipient: [20]u8,
    state_root: [32]u8,
    receipts_root: [32]u8,
    logs_bloom: [256]u8,
    prev_randao: [32]u8,
    block_number: u64,
    gas_limit: u64,
    gas_used: u64,
    timestamp: u64,
    extra_data: List(u8, MAX_EXTRA_DATA_BYTES),
    base_fee_per_gas: u256,
    block_hash: [32]u8,
    transactions: List(List(u8, MAX_BYTES_PER_TRANSACTION), MAX_TRANSACTIONS_PER_PAYLOAD),
    withdrawals: List(Withdrawal, MAX_WITHDRAWALS_PER_PAYLOAD),
    blob_gas_used: u64,
    excess_blob_gas: u64,
    block_access_list: List(u8, MAX_BLOCK_ACCESS_LIST_BYTES),
    slot_number: u64,
};

pub const DepositRequest = struct {
    pubkey: [48]u8,
    withdrawal_credentials: [32]u8,
    amount: u64,
    signature: [96]u8,
    index: u64,
};

pub const WithdrawalRequest = struct {
    source_address: [20]u8,
    validator_pubkey: [48]u8,
    amount: u64,
};

pub const ConsolidationRequest = struct {
    source_address: [20]u8,
    source_pubkey: [48]u8,
    target_pubkey: [48]u8,
};

pub const ExecutionRequests = struct {
    deposits: List(DepositRequest, MAX_DEPOSIT_REQUESTS_PER_PAYLOAD),
    withdrawals: List(WithdrawalRequest, MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD),
    consolidations: List(ConsolidationRequest, MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD),
};

pub const NewPayloadRequest = struct {
    execution_payload: ExecutionPayload,
    versioned_hashes: List([32]u8, MAX_BLOB_COMMITMENTS_PER_BLOCK),
    parent_beacon_block_root: [32]u8,
    execution_requests: ExecutionRequests,
};

pub const ExecutionWitness = struct {
    state: List(List(u8, MAX_BYTES_PER_WITNESS_NODE), MAX_WITNESS_NODES),
    codes: List(List(u8, MAX_BYTES_PER_CODE), MAX_WITNESS_CODES),
    headers: List(List(u8, MAX_BYTES_PER_HEADER), MAX_WITNESS_HEADERS),
};

pub const ForkActivation = struct {
    block_number: List(u64, MAX_OPTIONAL_FORK_ACTIVATION_VALUES),
    timestamp: List(u64, MAX_OPTIONAL_FORK_ACTIVATION_VALUES),
};

pub const BlobSchedule = struct {
    target: u64,
    max: u64,
    base_fee_update_fraction: u64,
};

pub const ForkConfig = struct {
    fork: u64,
    activation: ForkActivation,
    blob_schedule: List(BlobSchedule, MAX_BLOB_SCHEDULES_PER_FORK),
};

pub const ChainConfig = struct {
    chain_id: u64,
    active_fork: ForkConfig,
};

pub const StatelessInput = struct {
    new_payload_request: NewPayloadRequest,
    witness: ExecutionWitness,
    chain_config: ChainConfig,
    public_keys: List([65]u8, MAX_PUBLIC_KEYS),
};

pub const StatelessValidationResult = struct {
    new_payload_request_root: [32]u8,
    successful_validation: bool,
    chain_config: ChainConfig,
};
