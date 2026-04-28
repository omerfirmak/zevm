pub fn blobBaseFee(excess_blob_gas: u64, update_fraction: u64) u256 {
    if (update_fraction == 0) return 1;
    // fake_exponential(1, excess_blob_gas, update_fraction)
    const denom: u256 = update_fraction;
    var i: u256 = 1;
    var output: u256 = 0;
    var accum: u256 = denom; // factor(1) * denominator
    while (accum > 0) {
        output += accum;
        accum = accum * excess_blob_gas / (denom * i);
        i += 1;
    }
    return output / denom;
}
