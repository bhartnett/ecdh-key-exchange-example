use std::io::{Read, Write};
use std::net::TcpStream;
use std::thread::sleep;
use std::time::Duration;
use ring::error::Unspecified;
use ring::rand::SystemRandom;
use ring::agreement::Algorithm;
use ring::agreement::X25519;
use ring::agreement::EphemeralPrivateKey;
use ring::agreement::PublicKey;
use ring::agreement::UnparsedPublicKey;
use ring::agreement::agree_ephemeral;
use ephemeral_ephemeral::ecdh_x25519;

const SERVER_HOST: &str = "127.0.0.1";
const SERVER_PORT: &str = "7654";
//const BUFFER_SIZE: usize = 50;

fn main() {
    // Connect to server
    let mut stream = TcpStream::connect(format!("{}:{}", SERVER_HOST, SERVER_PORT)).unwrap();

    // Run the ephemeral to ephemeral key exchange as the client and return the session keys.
    // Two session keys are returned, one for each direction of communication between the client and server.
    // HKDF is used to derive the session keys from the output of the ECDH key exchange.
    let (client_to_server, server_to_client) = ecdh_x25519("CLIENT", &mut stream).unwrap();

    // run AEAD to encrypt a stream of data in each direction

    // loop {
    //     // write to stream
    //     let request = "Request data\n";
    //     stream.write(request.as_bytes()).unwrap();
    //
    //     // read from stream
    //     stream.read(&mut buffer).unwrap();
    //     println!("Client received response: {:?}", String::from_utf8(buffer.to_vec()).unwrap());
    //
    //     sleep(Duration::new(2, 0));
    // }

}