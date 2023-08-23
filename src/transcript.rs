use fluent_hash::Hash;
use fluent_hash::Hashing::Sha256;

pub struct HashTranscript {
    hash: Hash
}

impl HashTranscript {

    pub fn new() -> Self {
        HashTranscript{ hash: Sha256.hash(b"") }
    }

    pub fn append(&mut self, bytes: &[u8]) {
        let mut ctx = Sha256.new_context();
        ctx.update(self.hash.as_bytes());
        ctx.update(bytes);

        self.hash = ctx.finish();
    }

    pub fn as_bytes(&self) -> &[u8] {
        println!("transcript = {}", self.hash.to_hex());
        self.hash.as_bytes()
    }

}