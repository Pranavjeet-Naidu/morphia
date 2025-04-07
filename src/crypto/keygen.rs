//! Key generation for the Paillier cryptosystem

use num_bigint::{BigUint, RandBigInt};
use num_integer::Integer;
use num_traits::{One, Zero};
 
use rand::thread_rng;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

/// Number of bits for prime numbers
const DEFAULT_KEY_SIZE: usize = 512;

/// Paillier public key
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PublicKey {
    pub n: BigUint,  // n = p*q
    pub n_squared: BigUint,  // n² = n*n
    pub g: BigUint,  // typically n+1
}

/// Paillier private key
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrivateKey {
    pub lambda: BigUint,  // lcm(p-1, q-1)
    pub mu: BigUint,      // g^lambda mod n² = 1 + lambda*n mod n²
    pub p: BigUint,       // First prime
    pub q: BigUint,       // Second prime
}

/// Generate a random prime of specified bit size
fn generate_prime(bits: usize) -> BigUint {
    let mut rng = thread_rng();
    loop {
        // Generate a random odd number of specified bit size
        let mut candidate = rng.gen_biguint(bits as u64);
        if candidate.bits() < bits as u64 {
            continue; // Ensure we have full bit length
        }
        
        // Make it odd
        if candidate.is_even() {
            candidate |= BigUint::one();
        }
        
        // Simple primality test (Miller-Rabin would be better for production)
        // This is a basic check for demo purposes
        if is_probably_prime(&candidate, 10) {
            return candidate;
        }
    }
}

/// Simple primality test
/// Returns true if the number is probably prime
fn is_probably_prime(n: &BigUint, k: usize) -> bool {
    if n <= &BigUint::from(3u32) {
        return n > &BigUint::one();
    }
    
    if n.is_even() {
        return false;
    }
    
    // Simple divisibility test by small primes
    let small_primes = [3u32, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53];
    for &p in &small_primes {
        if n % p == BigUint::zero() && n != &BigUint::from(p) {
            return false;
        }
    }
    
    // For a real implementation, we should use the Miller-Rabin test here
    // But for this demo, we'll use a simple Fermat test
    let mut rng = thread_rng();
    for _ in 0..k {
        let a = rng.gen_biguint_range(&BigUint::from(2u32), n);
        let res = a.modpow(&(n - BigUint::one()), n);
        if res != BigUint::one() {
            return false;
        }
    }
    
    true
}

/// Generate Paillier key pair
pub fn generate_keypair(key_size: Option<usize>) -> (PublicKey, PrivateKey) {
    let bits = key_size.unwrap_or(DEFAULT_KEY_SIZE);
    
    // Generate two random primes of half the requested bit size
    let p = generate_prime(bits / 2);
    let q = generate_prime(bits / 2);
    
    // Calculate n = p*q and n² = n*n
    let n = &p * &q;
    let n_squared = &n * &n;
    
    // Calculate λ = lcm(p-1, q-1)
    let p_minus_1 = &p - BigUint::one();
    let q_minus_1 = &q - BigUint::one();
    let lambda = p_minus_1.lcm(&q_minus_1);
    
    // Choose g = n+1, which is a common choice for Paillier
    let g = &n + BigUint::one();
    
    // Compute μ = (L(g^λ mod n²))^(-1) mod n where L(x) = (x-1)/n
    // For g = n+1, g^λ mod n² = (1 + λ*n) mod n²
    let _g_lambda_mod_n_squared = (BigUint::one() + &n * &lambda) % &n_squared;
    
    // L(g^λ mod n²) = (g^λ mod n² - 1) / n = λ
    
    // Calculate μ = λ^(-1) mod n
    // This is equivalent to finding multiplicative inverse of λ modulo n
    let mu = calculate_mu(&lambda, &n);
    
    let public_key = PublicKey {
        n: n.clone(),
        n_squared: n_squared,
        g: g,
    };
    
    let private_key = PrivateKey {
        lambda: lambda,
        mu: mu,
        p: p,
        q: q,
    };
    
    (public_key, private_key)
}

/// Calculate μ = λ^(-1) mod n
fn calculate_mu(lambda: &BigUint, n: &BigUint) -> BigUint {
    // Use the Extended Euclidean Algorithm to find the modular inverse
    // For BigUint, we implement a version that works with positive numbers
    fn extended_gcd(a: &BigUint, b: &BigUint) -> (BigUint, BigUint, BigUint) {
        if b.is_zero() {
            return (a.clone(), BigUint::one(), BigUint::zero());
        }
        
        let (g, x, y) = extended_gcd(b, &(a % b));
        
        // We need to ensure s = x - (a/b)*y is non-negative
        let q = a / b;
        let t = q * &y;
        
        if x >= t {
            (g, x - t, y)
        } else {
            // We need to add enough multiples of b to make x - q*y non-negative
            let additional = (t.clone() - &x + b - BigUint::one()) / b;
            let x_adjusted = x + (additional * b);
            (g, x_adjusted - t, y)
        }
    }
    
    // Calculate modular inverse using extended GCD
    let (gcd, x, _) = extended_gcd(lambda, n);
    
    // Ensure lambda and n are coprime (gcd should be 1)
    if gcd != BigUint::one() {
        panic!("Modular inverse doesn't exist because gcd(lambda, n) != 1");
    }
    
    // Ensure the result is in range [0, n-1]
    x % n
}

/// Save keys to files
pub fn save_keys(public_key: &PublicKey, private_key: &PrivateKey, dir: &str) -> Result<(), String> {
    // Create directory if it doesn't exist
    let path = Path::new(dir);
    if !path.exists() {
        fs::create_dir_all(path).map_err(|e| format!("Failed to create directory: {}", e))?;
    }
    
    // Save public key
    let public_key_path = path.join("public_key.json");
    let public_key_json = serde_json::to_string_pretty(public_key)
        .map_err(|e| format!("Failed to serialize public key: {}", e))?;
    fs::write(&public_key_path, public_key_json)
        .map_err(|e| format!("Failed to write public key: {}", e))?;
    
    // Save private key
    let private_key_path = path.join("private_key.json");
    let private_key_json = serde_json::to_string_pretty(private_key)
        .map_err(|e| format!("Failed to serialize private key: {}", e))?;
    fs::write(&private_key_path, private_key_json)
        .map_err(|e| format!("Failed to write private key: {}", e))?;
    
    Ok(())
}

/// Load public key from file
pub fn load_public_key(dir: &str) -> Result<PublicKey, String> {
    let public_key_path = Path::new(dir).join("public_key.json");
    let public_key_json = fs::read_to_string(&public_key_path)
        .map_err(|e| format!("Failed to read public key: {}", e))?;
    let public_key = serde_json::from_str(&public_key_json)
        .map_err(|e| format!("Failed to deserialize public key: {}", e))?;
    Ok(public_key)
}

/// Load private key from file
pub fn load_private_key(dir: &str) -> Result<PrivateKey, String> {
    let private_key_path = Path::new(dir).join("private_key.json");
    let private_key_json = fs::read_to_string(&private_key_path)
        .map_err(|e| format!("Failed to read private key: {}", e))?;
    let private_key = serde_json::from_str(&private_key_json)
        .map_err(|e| format!("Failed to deserialize private key: {}", e))?;
    Ok(private_key)
}