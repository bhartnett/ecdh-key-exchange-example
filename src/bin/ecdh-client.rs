use std::io::{Read, Write};
use std::net::TcpStream;
use std::thread::sleep;
use std::time::Duration;

use ecdh_key_exchange_examples::aead::{AeadDecrypter, AeadEncrypter};
use ecdh_key_exchange_examples::ecdh::EcdhEphemeralKeyExchange;

const SERVER_HOST: &str = "127.0.0.1";
const SERVER_PORT: &str = "7654";
const BUFFER_SIZE: usize = 256;

fn main() {
    // Connect to server
    let mut stream = TcpStream::connect(format!("{}:{}", SERVER_HOST, SERVER_PORT)).unwrap();

    // Run the ephemeral to ephemeral key exchange as the client and return the session keys.
    // Two session keys are returned, one for each direction of communication between the client and server.
    // HKDF is used to derive the session keys from the output of the ECDH key exchange.
    let ecdh = EcdhEphemeralKeyExchange::new_client();
    let (client_to_server, server_to_client) = ecdh.run(&mut stream).unwrap();
    let mut encrypter = AeadEncrypter::new(&client_to_server);
    let mut decrypter = AeadDecrypter::new(&server_to_client);

    let mut counter: u32 = 0;
    loop {
        counter += 1;

        // write to stream
        let request = format!("Hello {}", counter);
        let ciphertext = encrypter.encrypt(request.as_bytes(), counter.to_string().as_bytes());
        let bytes_written = stream.write(&ciphertext).unwrap();
        println!("Client sent request {:?} bytes", bytes_written);

        // read from stream
        let mut buffer = [0; BUFFER_SIZE];
        let bytes_read = stream.read(&mut buffer).unwrap();
        let plaintext = decrypter.decrypt(&buffer[..bytes_read], counter.to_string().as_bytes());
        println!("Client received request: {:?}", String::from_utf8(plaintext).unwrap());
    
        sleep(Duration::new(5, 0));
    }

}