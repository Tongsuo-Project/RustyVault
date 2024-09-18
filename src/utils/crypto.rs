use blake2b_simd::Params;

pub fn blake2b256_hash(key: &str) -> Vec<u8> {
    let hash = Params::new().hash_length(32).to_state().update(key.as_bytes()).finalize();
    hash.as_bytes().to_vec()
}
