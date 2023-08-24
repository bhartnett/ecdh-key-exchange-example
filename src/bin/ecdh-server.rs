use std::io;
use std::io::{Error, ErrorKind, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread::sleep;
use std::time::Duration;

use ecdh_key_exchange_example::aead::{AeadDecrypter, AeadEncrypter};
use ecdh_key_exchange_example::ecdh::EcdhEphemeralKeyExchange;
use ecdh_key_exchange_example::transcript::HashTranscript;

const SERVER_HOST: &str = "127.0.0.1";
const SERVER_PORT: &str = "7654";
const BUFFER_SIZE: usize = 256;

fn main() {
    // Create a new socket
    let listener = TcpListener::bind(format!("{}:{}", SERVER_HOST, SERVER_PORT))
        .expect("Unable to bind socket to address");

    loop {
        // Create a new connection with the client
        let connection = listener.accept();
        if connection.is_err() {
            println!("Unable to accept connection from client");
            sleep(Duration::new(2, 0));
            continue;
        }
        let (stream, address) = connection.unwrap();
        println!("Connection established with client at {:?}", address);

        if handle_session(stream).is_err() {
            println!("Server unable to handle session with client at {}", address);
            sleep(Duration::new(2, 0));
            continue;
        }
    }
}

fn handle_session(mut stream: TcpStream) -> io::Result<usize> {
    // Run the ephemeral to ephemeral key exchange as the server and return the session keys.
    let mut ecdh = EcdhEphemeralKeyExchange::new_server();
    let (client_to_server, server_to_client) = ecdh.run(&mut stream)
        .map_err(|_e| Error::new(ErrorKind::Other, "Key exchange failed"))?;

    let mut transcript = HashTranscript::new();
    transcript.append(&ecdh.client_pub_key().unwrap());
    transcript.append(&ecdh.server_pub_key().unwrap());

    let mut decrypter = AeadDecrypter::new(&client_to_server);
    let mut encrypter = AeadEncrypter::new(&server_to_client);

    let mut counter = 0;
    loop {
        counter += 1;

        // read from stream
        let mut buffer = [0; BUFFER_SIZE];
        let bytes_read = stream.read(&mut buffer)?;
        //println!("read_count: {:?}", bytes_read);
        let plaintext = decrypter.decrypt(&buffer[..bytes_read], transcript.as_bytes())
            .map_err(|_e| Error::new(ErrorKind::Other, "Decryption failed"))?;
        transcript.append(&plaintext);
        println!("Server received request: {:?}", String::from_utf8(plaintext)
            .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?);

        // write to stream
        let response = format!("World {}", counter);
        let ciphertext = encrypter.encrypt(response.as_bytes(), transcript.as_bytes())
            .map_err(|_e| Error::new(ErrorKind::Other, "Encryption failed"))?;
        transcript.append(response.as_bytes());
        let bytes_written = stream.write(&ciphertext)?;
        println!("Server sent response {:?} bytes", bytes_written);
    }
}
