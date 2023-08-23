use std::io;
use std::io::{Error, ErrorKind, Read, Write};
use std::net::TcpStream;
use std::thread::sleep;
use std::time::Duration;

use ecdh_key_exchange_examples::aead::{AeadDecrypter, AeadEncrypter};
use ecdh_key_exchange_examples::ecdh::EcdhEphemeralKeyExchange;
use ecdh_key_exchange_examples::transcript::HashTranscript;

const SERVER_HOST: &str = "127.0.0.1";
const SERVER_PORT: &str = "7654";
const BUFFER_SIZE: usize = 256;

fn main() {
     loop {
         // Connect to server
         let connection = TcpStream::connect(format!("{}:{}", SERVER_HOST, SERVER_PORT));
         if connection.is_err() {
             println!("Client unable to connect to server at {}:{}", SERVER_HOST, SERVER_PORT);
             sleep(Duration::new(2, 0));
             continue;
         }

         println!("Connection established with server at {}:{}", SERVER_HOST, SERVER_PORT);

         if handle_session(connection.unwrap()).is_err() {
             println!("Client unable to handle connection with server at {}:{}", SERVER_HOST, SERVER_PORT);
             sleep(Duration::new(2, 0));
             continue;
         }
     }
}

fn handle_session(mut stream: TcpStream) -> io::Result<usize> {
    // Run the ephemeral to ephemeral key exchange as the client and return the session keys.
    let mut ecdh = EcdhEphemeralKeyExchange::new_client();
    let (client_to_server, server_to_client) = ecdh.run(&mut stream)
        .map_err(|_e| Error::new(ErrorKind::Other, "Key exchange failed"))?;

    let mut transcript = HashTranscript::new();
    transcript.append(&ecdh.client_pub_key().unwrap());
    transcript.append(&ecdh.server_pub_key().unwrap());

    let mut encrypter = AeadEncrypter::new(&client_to_server);
    let mut decrypter = AeadDecrypter::new(&server_to_client);

    let mut counter: u32 = 0;
    loop {
        counter += 1;

        // write to stream
        let request = format!("Hello {}", counter);
        let ciphertext = encrypter.encrypt(request.as_bytes(), transcript.as_bytes())
            .map_err(|_e| Error::new(ErrorKind::Other, "Encryption failed"))?;
        transcript.append(request.as_bytes());
        let bytes_written = stream.write(&ciphertext)?;
        println!("Client sent request {:?} bytes", bytes_written);

        // read from stream
        let mut buffer = [0; BUFFER_SIZE];
        let bytes_read = stream.read(&mut buffer)?;
        let plaintext = decrypter.decrypt(&buffer[..bytes_read], transcript.as_bytes())
            .map_err(|_e| Error::new(ErrorKind::Other, "Decryption failed"))?;
        transcript.append(&plaintext);
        println!("Client received response: {:?}", String::from_utf8(plaintext)
            .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?);

        sleep(Duration::new(5, 0));
    }
}