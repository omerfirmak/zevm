// Key type for the global contract state storage
pub const StorageLookup = struct {
    address: u256,
    slot: u256,
};

pub const Account = struct {
    nonce: u256,
    balance: u256,
    storage_hash: u256,
    code_hash: u256,

    pub fn isEmptyAccount(self: *const Account) bool {
        return self.nonce == 0 and self.balance == 0 and self.code_hash == empty_code_hash;
    }
};

// keccak256("") — used to identify accounts with no deployed code
pub const empty_code_hash = 0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470;
// keccak256 of an empty trie — placeholder for accounts with no storage
pub const empty_root_hash = 0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421;
