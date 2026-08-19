const std = @import("std");
const ssz_utils = @import("ssz").utils;
const List = ssz_utils.List;
const ProgressiveList = ssz_utils.ProgressiveList;
const ProgressiveByteList = ssz_utils.ProgressiveByteList;

const MAX_EXTRA_DATA_BYTES = 32;
const MAX_WITNESS_HEADERS = 256;
const MAX_BYTES_PER_WITNESS_NODE = 1 << 10;
const MAX_BYTES_PER_CODE = 1 << 16;
const MAX_BYTES_PER_HEADER = 1 << 10;
const PUBLIC_KEY_BYTES = 65;

pub const Withdrawal = struct {
    index: u64,
    validator_index: u64,
    address: [20]u8,
    amount: u64,
};

pub const ExecutionPayload = struct {
    pub const ssz_progressive_container = true;

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
    transactions: ProgressiveList(ProgressiveByteList),
    withdrawals: ProgressiveList(Withdrawal),
    blob_gas_used: u64,
    excess_blob_gas: u64,
    block_access_list: ProgressiveByteList,
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

pub const BuilderDepositRequest = struct {
    pubkey: [48]u8,
    withdrawal_credentials: [32]u8,
    amount: u64,
    signature: [96]u8,
};

pub const BuilderExitRequest = struct {
    source_address: [20]u8,
    pubkey: [48]u8,
};

pub const ExecutionRequests = struct {
    pub const ssz_progressive_container = true;

    deposits: ProgressiveList(DepositRequest),
    withdrawals: ProgressiveList(WithdrawalRequest),
    consolidations: ProgressiveList(ConsolidationRequest),
    builder_deposits: ProgressiveList(BuilderDepositRequest),
    builder_exits: ProgressiveList(BuilderExitRequest),
};

pub const NewPayloadRequest = struct {
    execution_payload: ExecutionPayload,
    versioned_hashes: ProgressiveList([32]u8),
    parent_beacon_block_root: [32]u8,
    execution_requests: ExecutionRequests,
};

pub const ExecutionWitness = struct {
    state: ProgressiveList(List(u8, MAX_BYTES_PER_WITNESS_NODE)),
    codes: ProgressiveList(List(u8, MAX_BYTES_PER_CODE)),
    headers: List(List(u8, MAX_BYTES_PER_HEADER), MAX_WITNESS_HEADERS),
};

pub const StatelessInput = struct {
    new_payload_request: NewPayloadRequest,
    witness: ExecutionWitness,
    chain_id: u64,
    public_keys: ProgressiveList([PUBLIC_KEY_BYTES]u8),
};

pub const StatelessValidationResult = struct {
    new_payload_request_root: [32]u8,
    successful_validation: bool,
    chain_id: u64,
    schema_id: u16,
};
