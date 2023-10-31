pub trait BlockCipher {
    fn new(key: &[u8], iv &[u8]) -> Self;
    fn encrypt(&mut self, input: &[u8]) -> Vec<u8>;
    fn decrypt(&mut self, input: &[u8]) -> Vec<u8>;
}
