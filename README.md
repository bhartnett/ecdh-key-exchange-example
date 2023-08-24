# ECDH Key Exchange Example

In this project I've implemented an example of an ECDH key exchange where both parties in the protocol generate ephemeral keys, 
then using these keys they generate a shared secret. Two session keys are then derived from the shared secret, one for each direction 
of the communication. The client and server connect to each other over TCP to create a connection, then establish an encrypted session
before sending encrypted messages to each other. The code uses the Ring cryptography library to implement the required crypto primitives. 
Usage of the various crypto primitives and design considerations are described below.

## ECDH
For key agreement we use the ephemeral X25519 ECDH key exchange implemented by Ring. See blog post on the topic here: https://web3developer.io/ecdh-key-agreement-in-rust-using-ring.
After creating a new connection between the client and server, we send and receive public keys over the TCP stream and then run the key
agreement algorithm to generate the shared secret. 

## HKDF
After generating the shared secret we need to run it through a key derivation function because the output of ECDH is not uniformly distributed.
We use HKDF for this purpose. See blog post on using HKDF here: https://web3developer.io/deriving-cryptographic-keys-with-hkdf-in-rust-using-ring.
Two session keys are generated by expanding the key material using the HKDF expand function and then splitting it into a pair. The public keys 
are passed into the HKDF context to bind the derived session keys to the specific public keys. 

## AEAD
We use AES-GCM to encrypt each message between the client and the server using one of the session keys for each direction of communication. 
See blog post on using authenticated encryption here: https://web3developer.io/authenticated-encryption-in-rust-using-ring.
AES-GCM requires passing a nonce to each encryption operation in order to randomise the encryption. The nonce must be unique and so we 
need to take care to never use repeated nonces for the same encryption key. The nonce doesn't need to be unpredictable so we simply use a 
counter starting from one which is incremented for each encryption operation. 

## Hash Transcript
A hash transcript is used to authenticate each AEAD decryption operation (similar to the design used in Noise Protocol Framework). We append the 
public keys and every message sent and received to the hash transcript in order to enforce that both the client and server are seeing the exact 
same messages in the same order. The hash transcript is implemented by using SHA-256 to hash new messages with the previous transcript hash which creates
a kind of hash chain.

## Start the Server
To start the server run:
```
cargo run --bin ecdh-server
```

## Start the Client
To start the client run:
```
cargo run --bin ecdh-client
```


