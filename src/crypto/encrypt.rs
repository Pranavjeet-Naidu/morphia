//! Encryption functions for the Paillier cryptosystem

use crate::crypto::keygen::PublicKey;
use num_bigint::{BigUint, RandBigInt};
use num_traits::One;
use rand::thread_rng;
use serde::{Deserialize, Serialize};

/// Encrypted value (ciphertext)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Ciphertext {
    pub value: BigUint,
}

/// Encrypt a message using the Paillier cryptosystem
/// 
/// The encryption formula is: c = g^m * r^n mod n^2
/// where:
/// - g is part of the public key (typically n+1)
/// - m is the message to encrypt
/// - r is a random number between 1 and n-1
/// - n is part of the public key
pub fn encrypt(public_key: &PublicKey, message: u64) -> Ciphertext {
    let m = BigUint::from(message);
    
    // Choose a random r in the range [1, n-1]
    let mut rng = thread_rng();
    let r = rng.gen_biguint_range(&BigUint::one(), &public_key.n);
    
    // c = g^m * r^n mod n^2
    let g_m = public_key.g.modpow(&m, &public_key.n_squared);
    let r_n = r.modpow(&public_key.n, &public_key.n_squared);
    
    let c = (g_m * r_n) % &public_key.n_squared;
    
    Ciphertext { value: c }
}

/// Save a ciphertext to a file
pub fn save_ciphertext(ciphertext: &Ciphertext, path: &str) -> Result<(), String> {
    let json = serde_json::to_string_pretty(ciphertext)
        .map_err(|e| format!("Failed to serialize ciphertext: {}", e))?;
    std::fs::write(path, json)
        .map_err(|e| format!("Failed to write ciphertext: {}", e))?;
    Ok(())
}

/// Load a ciphertext from a file
pub fn load_ciphertext(path: &str) -> Result<Ciphertext, String> {
    let json = std::fs::read_to_string(path)
        .map_err(|e| format!("Failed to read ciphertext: {}", e))?;
    let ciphertext = serde_json::from_str(&json)
        .map_err(|e| format!("Failed to deserialize ciphertext: {}", e))?;
    Ok(ciphertext)
}