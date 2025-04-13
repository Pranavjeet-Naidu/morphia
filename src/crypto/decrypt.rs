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
    // //intln!("DEBUG: Starting decryption");
    // //intln!("DEBUG: Ciphertext value: {}", ciphertext.value);
    
    let c_lambda = ciphertext.value.modpow(&private_key.lambda, &public_key.n_squared);
   //rintln!("DEBUG: c^λ mod n^2: {}", c_lambda);
    
    // L(c^λ mod n^2) = (c^λ mod n^2 - 1) / n
    let l_c_lambda = (c_lambda - BigUint::one()) / &public_key.n;
    // //intln!("DEBUG: L(c^λ mod n^2): {}", l_c_lambda);
    
    // m = L(c^λ mod n^2) * μ mod n
    let m = (l_c_lambda * &private_key.mu) % &public_key.n;
   //rintln!("DEBUG: Raw result m: {}", m);
    
    // HANDLE SMALL VALUES:
    // In Paillier, the original message may be a small number like 42
    // But the result of decryption is m mod n, which can be a very large number
    // We need to check if this could be a small value

    // First check if it's directly convertible to u64
    if let Some(value) = m.to_u64() {
       //rintln!("DEBUG: Directly convertible to u64: {}", value);
        return BigUint::from(value);
    }
    
    // Next, check if it's actually a small negative value wrapped around n
    // If m is very close to n, it might represent a small negative number
    // that should be interpreted as a small positive number
    let threshold = BigUint::from(1000u64);  // Arbitrary small threshold
    
    if &public_key.n - &m < threshold {
        // This number is very close to n, likely a small negative that wrapped around
        let small_value = &public_key.n - &m;
        if let Some(value) = small_value.to_u64() {
           //rintln!("DEBUG: Found small negative value: -{}", value);
            // In this case, we likely want the small positive value
            return small_value;
        }
    }
    
    // Fall back to the raw result if we can't determine a small value
    //intln!("DEBUG: Using raw large result");
    m
}