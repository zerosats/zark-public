// Injective proof-ABI encoding. Canonical application bytes remain unchanged.
// Every complete chunk is 31 bytes, strictly below the native field modulus.
// The final chunk uses exactly N % 31 bytes (31 when divisible), without padding.
pub fn pack<let N:u32, let K:u32>(bytes:[u8;N]) -> [Field;K] {
    assert(K == (N+30)/31, "packing chunk count");
    let mut result = [0 as Field;K];
    for i in 0..N {
        result[i/31] = result[i/31]*256 + bytes[i] as Field;
    }
    result
}

pub fn bind<let N:u32, let K:u32>(bytes:[u8;N], public:[Field;K]) {
    assert(public == pack::<N,K>(bytes), "packed statement binding");
}
