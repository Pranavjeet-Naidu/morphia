//! Decryption functions for the Paillier cryptosystem

use crate::crypto::encrypt::Ciphertext;
use crate::crypto::keygen::{PrivateKey, PublicKey};
use num_bigint::BigUint;
use num_traits::One;

/// Decrypt a ciphertext using the Paillier cryptosystem
///
/// The decryption formula is: m = L(c^λ mod n^2) * μ mod n
/// where:
/// - L(x) = (x-1)/n
/// - λ and μ are part of the private key
pub fn decrypt(public_key: &PublicKey, private_key: &PrivateKey, ciphertext: &Ciphertext) -> u64 {
    // c^λ mod n^2
    let c_lambda = ciphertext.value.modpow(&private_key.lambda, &public_key.n_squared);
    
    // L(c^λ mod n^2) = (c^λ mod n^2 - 1) / n
    let l_c_lambda = (c_lambda - BigUint::one()) / &public_key.n;
    
    // m = L(c^λ mod n^2) * μ mod n
    let m = (l_c_lambda * &private_key.mu) % &public_key.n;
    
    // Convert BigUint to u64
    // For larger numbers, we might need a different approach
    m.to_u64().unwrap()
}