pub mod aead;
pub mod ecdh;

// TODO:
// implement aead hash chaining.
// Improve resiliency of client and server.

// Refactor and simplify workspace structure. Do I need to use a workspace at all? Maybe can use a single project with many binaries.
// How to correctly use the HKDF?

// Need to restart nonce to zero on error. Basically if any error occurs then need to restart the session fresh.
// Improve error handling. Perhaps remove calls to unwrap.
// Document how to run each scenario in the readme.