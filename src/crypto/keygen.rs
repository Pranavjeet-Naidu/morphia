//! Key generation for the Paillier cryptosystem

use num_bigint::BigUint;
use num_integer::Integer;
use num_traits::{One, Zero};
use rand::thread_rng;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

// Add RSA crate for secure prime generation
use rsa::traits::PrivateKeyParts; // Added PrivateKeyParts here
use rsa::RsaPrivateKey;

/// Number of bits for prime numbers
const DEFAULT_KEY_SIZE: usize = 512;

/// Module to handle BigUint serialization
mod bigint_serialization {
    use num_bigint::BigUint;
    use serde::{Deserializer, Serializer};
    use serde::de::{self, Visitor};
    use std::fmt;
    use std::str::FromStr;

    pub fn serialize<S>(bigint: &BigUint, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&bigint.to_string())
    }

    struct BigUintVisitor;

    impl<'de> Visitor<'de> for BigUintVisitor {
        type Value = BigUint;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("a string representing a big integer")
        }

        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            BigUint::from_str(v).map_err(de::Error::custom)
        }

        fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            BigUint::from_str(&v).map_err(de::Error::custom)
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<BigUint, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(BigUintVisitor)
    }
}

/// Paillier public key
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PublicKey {
    #[serde(with = "bigint_serialization")]
    pub n: BigUint,
    #[serde(with = "bigint_serialization")]
    pub n_squared: BigUint,
    #[serde(with = "bigint_serialization")]
    pub g: BigUint,
}

/// Paillier private key
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrivateKey {
    #[serde(with = "bigint_serialization")]
    pub lambda: BigUint,  // lcm(p-1, q-1)
    #[serde(with = "bigint_serialization")]
    pub mu: BigUint,      // g^lambda mod n² = 1 + lambda*n mod n²
    #[serde(with = "bigint_serialization")]
    pub p: BigUint,       // First prime
    #[serde(with = "bigint_serialization")]
    pub q: BigUint,       // Second prime
}

/// Generate cryptographically secure primes using the RSA crate
/// Returns a tuple of two primes suitable for RSA/Paillier
fn generate_secure_primes(bits: usize) -> (BigUint, BigUint) {
    // The RSA crate already implements secure prime generation with appropriate checks
    // We'll use it to generate an RSA key of twice the requested bits (since each prime is half)
    let mut rng = thread_rng();
    
    // Generate RSA private key which includes two primes with proper properties
    let private_key = RsaPrivateKey::new(&mut rng, bits)
        .expect("Failed to generate RSA key");
    
    // Extract the primes (the RSA crate ensures they have appropriate properties)
    let primes = private_key.primes();
    
    // Convert from RSA's BigUint to num-bigint's BigUint
    let p_bytes = primes[0].to_bytes_be();
    let q_bytes = primes[1].to_bytes_be();
    
    let p = BigUint::from_bytes_be(&p_bytes);
    let q = BigUint::from_bytes_be(&q_bytes);
    
    (p, q)
}

pub fn generate_keypair(key_size: Option<usize>) -> (PublicKey, PrivateKey) {
    let bits = key_size.unwrap_or(DEFAULT_KEY_SIZE);
    
    // Generate two secure primes with proper properties for RSA/Paillier
    let (p, q) = generate_secure_primes(bits);
    
    // Calculate n = p*q and n² = n*n
    let n = &p * &q;
    let n_squared = &n * &n;
    
    // Calculate λ = lcm(p-1, q-1)
    let p_minus_1 = &p - BigUint::one();
    let q_minus_1 = &q - BigUint::one();
    let lambda = p_minus_1.lcm(&q_minus_1);
    
    // Choose g = n+1, which is a common choice for Paillier
    let g = &n + BigUint::one();
    
    // Compute g^λ mod n²
    // Note: For large keys, computing g^λ directly is inefficient
    // But we're using the direct mathematical approach as requested
    let not_u = g.modpow(&lambda, &n_squared);
    
    // Compute L(not_u) = (not_u - 1) / n
    let l_result = (not_u - BigUint::one()) / &n;
    
    // Compute μ = L(not_u)^(-1) mod n directly using modular inverse
    // Calculate modular inverse directly
    let mu = {
        let (gcd, x, _) = extended_gcd(&l_result, &n);
        
        // Ensure l_result and n are coprime (gcd should be 1)
        if gcd != BigUint::one() {
            panic!("Modular inverse doesn't exist because gcd(L(not_u), n) != 1");
        }
        
        // Ensure the result is in range [0, n-1]
        x % &n
    };
    
    let public_key = PublicKey {
        n: n.clone(),
        n_squared,
        g,
    };
    
    let private_key = PrivateKey {
        lambda,
        mu,
        p,
        q,
    };
    
    (public_key, private_key)
}


// Helper function for extended GCD calculation
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
    
    // // Print key details to terminal
    // println!("\nPublic Key Details:");
    // println!("n = {} ({})", public_key.n, public_key.n.bits());
    // println!("g = {} ({})", public_key.g, public_key.g.bits());
    
    // println!("\nPrivate Key Details:");
    // println!("lambda = {} ({})", private_key.lambda, private_key.lambda.bits());
    // println!("mu = {} ({})", private_key.mu, private_key.mu.bits());

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