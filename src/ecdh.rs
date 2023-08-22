use std::io::{Read, Write};
use std::net::TcpStream;

use ring::agreement::{agree_ephemeral, EphemeralPrivateKey, PublicKey, UnparsedPublicKey, X25519};
use ring::digest::SHA256_OUTPUT_LEN;
use ring::error::Unspecified;
use ring::hkdf::{HKDF_SHA256, KeyType, Prk, Salt};
use ring::rand::SystemRandom;

use crate::ecdh::Actor::{CLIENT, SERVER};

#[derive(Debug)]
enum Actor {
    CLIENT, SERVER
}

pub struct EcdhEphemeralKeyExchange {
    actor: Actor,
    rand: SystemRandom
}

impl EcdhEphemeralKeyExchange {

    pub fn new_client() -> EcdhEphemeralKeyExchange {
        EcdhEphemeralKeyExchange { actor: CLIENT, rand: SystemRandom::new() }
    }

    pub fn new_server() -> EcdhEphemeralKeyExchange {
        EcdhEphemeralKeyExchange { actor: SERVER, rand: SystemRandom::new() }
    }

    pub fn run(&self, stream: &mut TcpStream) -> Result<(Vec<u8>, Vec<u8>), Unspecified> {
        let alg = &X25519;
        let my_private_key: EphemeralPrivateKey = EphemeralPrivateKey::generate(alg, &self.rand)?;
        let my_public_key: PublicKey = my_private_key.compute_public_key()?;
        println!("{:?}: public_key = {}", self.actor, hex::encode(my_public_key.as_ref()));

        // Send our public key to the peer
        stream.write_all(my_public_key.as_ref()).unwrap();

        // Receive a public key from the peer
        let mut peer_public_key = [0u8; 32];
        stream.read_exact(&mut peer_public_key).unwrap();
        println!("{:?}: peer_public_key = {}", self.actor, hex::encode(peer_public_key.as_ref()));

        // The peer public key needs to be parsed before use so wrap it creating as an instance of UnparsedPublicKey
        let peer_public_key = UnparsedPublicKey::new(alg, peer_public_key);

        // run ECDH to agree on a shared secret
        agree_ephemeral(my_private_key,
                        &peer_public_key,
                        Unspecified, // error to return on failure
                        |shared_secret| Self::kdf(shared_secret))
    }

    fn kdf(shared_secret: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Unspecified> {
        // As recommended in RFC 7748 we should apply a KDF on the key material here
        let salt = Salt::new(HKDF_SHA256, b"salt bytes"); // TODO: what to use for salt?
        let pseudo_rand_key: Prk = salt.extract(shared_secret);
        //let context_data = [my_public_key.as_ref(), peer_public_key.bytes()]; // TODO: what to use for context?
        let context_data = [];

        const SESSION_KEY_LEN: usize = 2 * SHA256_OUTPUT_LEN;
        struct SessionKeyType;
        impl KeyType for SessionKeyType {
            fn len(&self) -> usize {
                SESSION_KEY_LEN
            }
        }

        let output_key_material = pseudo_rand_key.expand(&context_data, SessionKeyType)?;
        let mut result = [0u8; SESSION_KEY_LEN];
        output_key_material.fill(&mut result).unwrap();
        //println!("{}: result = {:?}", actor, hex::encode(result)); // don't print this in production

        let session_key = result.split_at(SESSION_KEY_LEN / 2);
        //println!("{}: session_key.0 = {:?}", actor, hex::encode(session_key.0)); // don't print this in production
        //println!("{}: session_key.1 = {:?}", actor, hex::encode(session_key.1)); // don't print this in production

        Ok((session_key.0.to_vec(), session_key.1.to_vec()))
    }
}