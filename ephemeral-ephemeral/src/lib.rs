use std::io::{Read, Write};
use std::net::TcpStream;
use ring::error::Unspecified;
use ring::rand::SystemRandom;
use ring::agreement::Algorithm;
use ring::agreement::X25519;
use ring::agreement::EphemeralPrivateKey;
use ring::agreement::PublicKey;
use ring::agreement::UnparsedPublicKey;
use ring::agreement::agree_ephemeral;
use ring::digest::SHA256_OUTPUT_LEN;
use ring::hkdf::{HKDF_SHA256, Okm, Prk, Salt};

pub fn ecdh_x25519(actor: &str, stream: &mut TcpStream) -> Result<(), Unspecified> {
    // Use a rand::SystemRandom as the source of entropy
    let rng = SystemRandom::new();

    // Select a key agreement algorithm. All agreement algorithms follow the same flow
    let alg: &Algorithm = &X25519;

    // Generate a private key and public key
    let my_private_key: EphemeralPrivateKey = EphemeralPrivateKey::generate(alg, &rng)?;
    let my_public_key: PublicKey = my_private_key.compute_public_key()?;
    // The EphemeralPrivateKey doesn't allow us to directly access the private key as designed
    println!("{}: public_key = {}", actor, hex::encode(my_public_key.as_ref()));

    // Send our public key to the peer here
    stream.write_all(my_public_key.as_ref()).unwrap();

    // Receive a public key from the peer
    let mut peer_public_key = [0u8; 32];
    stream.read_exact(&mut peer_public_key).unwrap();
    println!("{}: peer_public_key = {}", actor, hex::encode(peer_public_key.as_ref()));

    // The peer public key needs to be parsed before use so wrap it creating as an instance of UnparsedPublicKey
    let peer_public_key = UnparsedPublicKey::new(alg, peer_public_key);

    // run ECDH to agree on a shared secret
    agree_ephemeral(my_private_key,
                    &peer_public_key,
                    Unspecified, // error to return on failure
                    |shared_secret: &[u8]| { // the result of the key agreement is passed to this lambda
                        println!("{}: shared_secret = {}", actor, hex::encode(shared_secret.as_ref())); // don't print this in production

                        // As recommended in RFC 7748 we should apply a KDF on the key material here before using in a real application
                        // We can return the derived key from the kdf here, otherwise we just return () if the key isn't needed outside this scope
                        // Derive a single output key using Salt::extract and Prk::expand
                        // TODO: hkdf
                        // let input_key_material = b"secret key";
                        // let salt = Salt::new(HKDF_SHA256, b"salt bytes");
                        // let pseudo_rand_key: Prk = salt.extract(input_key_material);
                        // let context_data = ["context field 1".as_bytes(), "context field 2".as_bytes()];
                        // let output_key_material: Okm<Algorithm> = pseudo_rand_key.expand(&context_data, HKDF_SHA256)?;
                        // let mut result = [0u8; SHA256_OUTPUT_LEN * 2];
                        // output_key_material.fill(&mut result)

                        Ok(())
                    })
}