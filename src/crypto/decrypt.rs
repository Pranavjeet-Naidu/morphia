//! Decryption functions for the Paillier cryptosystem

use crate::crypto::encrypt::Ciphertext;
use crate::crypto::keygen::{PrivateKey, PublicKey};
use num_bigint::BigUint;
use num_traits::{One, ToPrimitive};

/// Decrypt a ciphertext using the Paillier cryptosystem
///
/// The decryption formula is: m = L(c^λ mod n^2) * μ mod n
/// where:
/// - L(x) = (x-1)/n
/// - λ and μ are part of the private key
pub fn decrypt(public_key: &PublicKey, private_key: &PrivateKey, ciphertext: &Ciphertext) -> BigUint {
    // c^λ mod n^2
    println!("DEBUG: Starting decryption");
    println!("DEBUG: Ciphertext value: {}", ciphertext.value);
    
    let c_lambda = ciphertext.value.modpow(&private_key.lambda, &public_key.n_squared);
    println!("DEBUG: c^λ mod n^2: {}", c_lambda);
    
    // L(c^λ mod n^2) = (c^λ mod n^2 - 1) / n
    let l_c_lambda = (c_lambda - BigUint::one()) / &public_key.n;
    println!("DEBUG: L(c^λ mod n^2): {}", l_c_lambda);
    
    // m = L(c^λ mod n^2) * μ mod n
    let m = (l_c_lambda * &private_key.mu) % &public_key.n;
    println!("DEBUG: Final result m: {}", m);
    
    // Check if it's convertible to u64
    match m.to_u64() {
        Some(value) => println!("DEBUG: Can be converted to u64: {}", value),
        None => println!("DEBUG: Too large for u64")
    }
    
    m
}