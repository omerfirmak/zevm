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
    extra_data: []const u8,
    base_fee_per_gas: u256,
    block_hash: [32]u8,
    transactions: [][]const u8,
    withdrawals: []Withdrawal,
    blob_gas_used: u64,
    excess_blob_gas: u64,
    block_access_list: []const u8,
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
    deposits: []DepositRequest,
    withdrawals: []WithdrawalRequest,
    consolidations: []ConsolidationRequest,
};

pub const NewPayloadRequest = struct {
    execution_payload: ExecutionPayload,
    versioned_hashes: [][32]u8,
    parent_beacon_block_root: [32]u8,
    execution_requests: ExecutionRequests,
};

pub const ExecutionWitness = struct {
    state: [][]const u8,
    codes: [][]const u8,
    headers: [][]const u8,
};

pub const ForkActivation = struct {
    block_number: []u64,
    timestamp: []u64,
};

pub const BlobSchedule = struct {
    target: u64,
    max: u64,
    base_fee_update_fraction: u64,
};

pub const ForkConfig = struct {
    fork: u64,
    activation: ForkActivation,
    blob_schedule: []BlobSchedule,
};

pub const ChainConfig = struct {
    chain_id: u64,
    active_fork: ForkConfig,
};

pub const StatelessInput = struct {
    new_payload_request: NewPayloadRequest,
    witness: ExecutionWitness,
    chain_config: ChainConfig,
    public_keys: [][48]u8,
};

pub const StatelessValidationResult = struct {
    new_payload_request_root: [32]u8,
    successful_validation: bool,
    chain_config: ChainConfig,
};
