use ring::aead::{Aad, AES_256_GCM, BoundKey, Nonce, NONCE_LEN, NonceSequence, OpeningKey, SealingKey, UnboundKey};
use ring::error::Unspecified;

pub struct CounterNonceSequence(u32);

impl NonceSequence for CounterNonceSequence {
    // called once for each seal operation
    fn advance(&mut self) -> Result<Nonce, Unspecified> {
        let mut nonce_bytes = vec![0; NONCE_LEN];
        nonce_bytes[8..].copy_from_slice(&self.0.to_be_bytes());
        //println!("nonce_bytes = {}", hex::encode(&nonce_bytes));

        self.0 += 1; // advance the counter
        Nonce::try_assume_unique_for_key(&nonce_bytes)
    }
}

pub struct AeadEncrypter {
    sealing_key: SealingKey<CounterNonceSequence>
}

impl AeadEncrypter {
    pub fn new(key: &[u8]) -> Self {
        let unbound_key = UnboundKey::new(&AES_256_GCM, &key).unwrap();

        AeadEncrypter {
            sealing_key: SealingKey::new(unbound_key, CounterNonceSequence(1))
        }
    }

    pub fn encrypt(&mut self, data: &[u8], associated_data: &[u8]) -> Result<Vec<u8>, Unspecified> {
        let associated_data = Aad::from(associated_data);

        let mut in_out = data.to_vec();
        let tag = self.sealing_key.seal_in_place_separate_tag(associated_data, &mut in_out)?;

        Ok([&in_out, tag.as_ref()].concat())
    }

}

pub struct AeadDecrypter {
    opening_key: OpeningKey<CounterNonceSequence>
}

impl AeadDecrypter {
    pub fn new(key: &[u8]) -> Self {
        let unbound_key = UnboundKey::new(&AES_256_GCM, &key).unwrap();

        AeadDecrypter {
            opening_key: OpeningKey::new(unbound_key, CounterNonceSequence(1))
        }
    }

    pub fn decrypt(&mut self, ciphertext: &[u8], associated_data: &[u8]) -> Result<Vec<u8>, Unspecified> {
        let associated_data = Aad::from(associated_data);

        let mut in_out = ciphertext.to_vec();
        Ok(self.opening_key.open_in_place(associated_data, &mut in_out)?.to_vec())
    }
}