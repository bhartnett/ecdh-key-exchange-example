use std::io::{Read, Write};
use std::net::TcpListener;

use ecdh_key_exchange_examples::aead::{AeadDecrypter, AeadEncrypter};
use ecdh_key_exchange_examples::ecdh::EcdhEphemeralKeyExchange;

const SERVER_HOST: &str = "127.0.0.1";
const SERVER_PORT: &str = "7654";
const BUFFER_SIZE: usize = 256;

fn main() {
    // Create a new socket
    let listener = TcpListener::bind(format!("{}:{}", SERVER_HOST, SERVER_PORT)).unwrap();

    loop {
        // Create a new connection with the client
        let (mut stream, address) = listener.accept().unwrap();
        println!("Connection established with client at {:?}", address);

        // Run the ephemeral to ephemeral key exchange as the server and return the session keys.
        // Two session keys are returned, one for each direction of communication between the client and server.
        // HKDF is used to derive the session keys from the output of the ECDH key exchange.
        let ecdh = EcdhEphemeralKeyExchange::new_server();
        let (client_to_server, server_to_client) = ecdh.run(&mut stream).unwrap();
        let mut decrypter = AeadDecrypter::new(&client_to_server);
        let mut encrypter = AeadEncrypter::new(&server_to_client);

        let mut counter = 0;
        loop {
            counter += 1;

            // read from stream
            let mut buffer = [0; BUFFER_SIZE];
            let bytes_read = stream.read(&mut buffer).unwrap();
            //println!("read_count: {:?}", bytes_read);
            let plaintext = decrypter.decrypt(&buffer[..bytes_read], counter.to_string().as_bytes());
            println!("Server received request: {:?}", String::from_utf8(plaintext).unwrap());

            // write to stream
            let response = format!("World {}", counter);
            let ciphertext = encrypter.encrypt(response.as_bytes(), counter.to_string().as_bytes());
            let bytes_written = stream.write(&ciphertext).unwrap();
            println!("Server sent response {:?} bytes", bytes_written);
        }

    }
}
