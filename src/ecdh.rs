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
    rand: SystemRandom,
    pub_key: Option<Vec<u8>>,
    peer_pub_key: Option<Vec<u8>>,
}

impl EcdhEphemeralKeyExchange {

    pub fn new_client() -> Self {
        Self::new(CLIENT)
    }

    pub fn new_server() -> Self {
        Self::new(SERVER)
    }

    fn new(actor: Actor) -> Self {
        EcdhEphemeralKeyExchange {
            actor,
            rand: SystemRandom::new(),
            pub_key: None,
            peer_pub_key: None
        }
    }

    pub fn client_pub_key(&self) -> Option<Vec<u8>> {
        match self.actor {
            CLIENT => return self.pub_key.clone(),
            SERVER => return self.peer_pub_key.clone()
        }
    }

    pub fn server_pub_key(&self) -> Option<Vec<u8>> {
        match self.actor {
            CLIENT => self.peer_pub_key.clone(),
            SERVER => self.pub_key.clone()
        }
    }

    pub fn run(&mut self, stream: &mut TcpStream) -> Result<(Vec<u8>, Vec<u8>), Unspecified> {
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

        // Store public keys for usage in the HashTranscript
        self.pub_key = Some(my_public_key.as_ref().to_vec());
        self.peer_pub_key = Some(peer_public_key.bytes().to_vec());

        // run ECDH to agree on a shared secret
        agree_ephemeral(my_private_key,
                        &peer_public_key,
                        |shared_secret| self.kdf(shared_secret))
    }



    fn kdf(&self, shared_secret: &[u8]) -> (Vec<u8>, Vec<u8>) {
        // As recommended in RFC 7748 we should apply a KDF on the key material here
        let salt = Salt::new(HKDF_SHA256, b""); // salt is optional
        let pseudo_rand_key: Prk = salt.extract(shared_secret);

        let mut context = self.client_pub_key().unwrap();
        context.append(&mut self.server_pub_key().unwrap());
        let context_data = [context.as_slice()];

        const SESSION_KEY_LEN: usize = 2 * SHA256_OUTPUT_LEN;
        struct SessionKeyType;
        impl KeyType for SessionKeyType {
            fn len(&self) -> usize {
                SESSION_KEY_LEN
            }
        }

        let output_key_material = pseudo_rand_key.expand(&context_data, SessionKeyType).unwrap();
        let mut result = [0u8; SESSION_KEY_LEN];
        output_key_material.fill(&mut result).unwrap();

        let session_key = result.split_at(SESSION_KEY_LEN / 2);
        (session_key.0.to_vec(), session_key.1.to_vec())
    }
}