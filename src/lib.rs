//! Morphia - A library for homomorphic encryption using the Paillier cryptosystem

pub mod crypto;
pub mod cli;

// Re-export main modules for easier access
pub use crypto::keygen;
pub use crypto::encrypt;
pub use crypto::decrypt;
pub use crypto::ops;