use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use ephemeral_ephemeral::ecdh_x25519;

const SERVER_HOST: &str = "127.0.0.1";
const SERVER_PORT: &str = "7654";
//const BUFFER_SIZE: usize = 50;


fn main() {
    // Create a new socket
    let listener = TcpListener::bind(format!("{}:{}", SERVER_HOST, SERVER_PORT)).unwrap();

    //loop {
        // Create a new connection with the client
        let (mut stream, address) = listener.accept().unwrap();
        println!("Connection established with client at {:?}", address);

    // Run the ephemeral to ephemeral key exchange as the server and return the session keys.
    // Two session keys are returned, one for each direction of communication between the client and server.
    // HKDF is used to derive the session keys from the output of the ECDH key exchange.
    let (client_to_server, server_to_client) = ecdh_x25519("SERVER", &mut stream).unwrap();

    //     loop {
    //         // Read and write using the connection
    //         handle_connection(&mut stream);
    //     }
    // }
}

// fn handle_connection(stream: &mut TcpStream) {
//     let mut buffer = [0; BUFFER_SIZE];
//
//     // read from stream
//     stream.read(&mut buffer).unwrap();
//     println!("Server received request: {:?}", String::from_utf8(buffer.to_vec()).unwrap());
//
//     // write to stream
//     let response = "Response data\n";
//     stream.write(response.as_bytes()).unwrap();
// }
