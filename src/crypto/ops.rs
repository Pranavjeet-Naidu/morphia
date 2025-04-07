//! Homomorphic operations for the Paillier cryptosystem

use crate::crypto::encrypt::Ciphertext;
use crate::crypto::keygen::PublicKey;
use num_bigint::BigUint;

/// Add two encrypted values homomorphically
///
/// In Paillier cryptosystem, homomorphic addition is performed
/// by multiplying ciphertexts modulo n²:
/// E(m1) * E(m2) mod n² = E(m1 + m2 mod n)
pub fn add(public_key: &PublicKey, a: &Ciphertext, b: &Ciphertext) -> Ciphertext {
    let sum = (&a.value * &b.value) % &public_key.n_squared;
    Ciphertext { value: sum }
}

/// Multiply an encrypted value by a plaintext constant homomorphically
///
/// In Paillier cryptosystem, homomorphic multiplication by a constant k is performed
/// by raising the ciphertext to the power of k modulo n²:
/// E(m)^k mod n² = E(k*m mod n)
pub fn multiply_by_constant(public_key: &PublicKey, a: &Ciphertext, k: u64) -> Ciphertext {
    let k_biguint = BigUint::from(k);
    let product = a.value.modpow(&k_biguint, &public_key.n_squared);
    Ciphertext { value: product }
}

/// Demonstrate homomorphic properties by showing that:
/// decrypt(add(encrypt(a), encrypt(b))) == a + b
/// decrypt(multiply_by_constant(encrypt(a), k)) == a * k
pub fn demo_homomorphic_properties(
    public_key: &PublicKey, 
    private_key: &crate::crypto::keygen::PrivateKey,
    a: u64,
    b: u64,
    k: u64
) -> (u64, u64, u64, u64) {
    use crate::crypto::{encrypt, decrypt};
    
    // Encrypt values
    let enc_a = encrypt::encrypt(public_key, a);
    let enc_b = encrypt::encrypt(public_key, b);
    
    // Perform homomorphic addition
    let enc_sum = add(public_key, &enc_a, &enc_b);
    let dec_sum = decrypt::decrypt(public_key, private_key, &enc_sum);
    
    // Perform homomorphic multiplication by constant
    let enc_prod = multiply_by_constant(public_key, &enc_a, k);
    let dec_prod = decrypt::decrypt(public_key, private_key, &enc_prod);
    
    // Return the decrypted results to verify homomorphic properties
    (a + b, dec_sum, a * k, dec_prod)
}