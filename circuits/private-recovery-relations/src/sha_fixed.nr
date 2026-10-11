// Fixed-length SHA256 padding/packing, with no unconstrained witness helpers.
// Compression itself is Noir's backend-constrained SHA256 black box.
pub fn digest<let N: u32>(msg: [u8; N]) -> [u8; 32] {
    let mut padded = [0; ((N + 9 + 63) / 64) * 64];
    for i in 0..N { padded[i] = msg[i]; }
    padded[N] = 128;
    let bit_len: u64 = N as u64 * 8;
    for i in 0..8 {
        padded[padded.len()-1-i] = ((bit_len >> (8*i as u64)) & 255) as u8;
    }
    let mut state: [u32; 8] = [0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19];
    for block in 0..padded.len()/64 {
        let mut words: [u32; 16] = [0; 16];
        for i in 0..16 {
            let p = block*64+i*4;
            words[i] = (padded[p] as u32 << 24) | (padded[p+1] as u32 << 16)
                | (padded[p+2] as u32 << 8) | padded[p+3] as u32;
        }
        state = std::hash::sha256_compression(words, state);
    }
    let mut out = [0; 32];
    for i in 0..8 {
        for j in 0..4 { out[4*i+j] = ((state[i] >> (24-8*j)) & 255) as u8; }
    }
    out
}

#[test]
fn sha256_abc() {
    assert(digest("abc".as_bytes()) == [186,120,22,191,143,1,207,234,65,65,64,222,93,174,34,35,176,3,97,163,150,23,122,156,180,16,255,97,242,0,21,173]);
}
