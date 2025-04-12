//! Key generation for the Paillier cryptosystem

use num_bigint::BigUint;
use num_integer::Integer;
use num_traits::One;  // Removed Zero import
use rand::thread_rng;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

// Add RSA crate for secure prime generation
use rsa::traits::PrivateKeyParts;
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
    pub mu: BigUint,      // L(g^lambda mod n²)^(-1) mod n
    #[serde(with = "bigint_serialization")]
    pub p: BigUint,       // First prime
    #[serde(with = "bigint_serialization")]
    pub q: BigUint,       // Second prime
}

/// Generate cryptographically secure primes using the RSA crate
fn generate_secure_primes(bits: usize) -> (BigUint, BigUint) {
    let mut rng = thread_rng();
    let private_key = RsaPrivateKey::new(&mut rng, bits)
        .expect("Failed to generate RSA key");
    
    let primes = private_key.primes();
    let p = BigUint::from_bytes_be(primes[0].to_bytes_be().as_slice());
    let q = BigUint::from_bytes_be(primes[1].to_bytes_be().as_slice());
    
    (p, q)
}

pub fn generate_keypair(key_size: Option<usize>) -> (PublicKey, PrivateKey) {
    let bits = key_size.unwrap_or(DEFAULT_KEY_SIZE);
    let (p, q) = generate_secure_primes(bits);
    
    let n = &p * &q;
    let n_squared = &n * &n;
    
    let p_minus_1 = &p - BigUint::one();
    let q_minus_1 = &q - BigUint::one();
    let lambda = p_minus_1.lcm(&q_minus_1);
    
    let g = &n + BigUint::one();
    let not_u = g.modpow(&lambda, &n_squared);
    let l_result = (not_u - BigUint::one()) / &n;
    
    // Corrected method name to modinv
    let mu = l_result.modinv(&n)
        .expect("Modular inverse doesn't exist");
    
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

/// Save keys to files
pub fn save_keys(public_key: &PublicKey, private_key: &PrivateKey, dir: &str) -> Result<(), String> {
    let path = Path::new(dir);
    if !path.exists() {
        fs::create_dir_all(path).map_err(|e| format!("Failed to create directory: {}", e))?;
    }
    
    let public_key_path = path.join("public_key.json");
    let public_key_json = serde_json::to_string_pretty(public_key)
        .map_err(|e| format!("Failed to serialize public key: {}", e))?;
    fs::write(&public_key_path, public_key_json)
        .map_err(|e| format!("Failed to write public key: {}", e))?;
    
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
    serde_json::from_str(&public_key_json)
        .map_err(|e| format!("Failed to deserialize public key: {}", e))
}

/// Load private key from file
pub fn load_private_key(dir: &str) -> Result<PrivateKey, String> {
    let private_key_path = Path::new(dir).join("private_key.json");
    let private_key_json = fs::read_to_string(&private_key_path)
        .map_err(|e| format!("Failed to read private key: {}", e))?;
    serde_json::from_str(&private_key_json)
        .map_err(|e| format!("Failed to deserialize private key: {}", e))
}

/// Get the registry of key pairs
pub fn get_key_registry() -> Result<Vec<String>, String> {
    let keys_dir = Path::new("keys");
    let registry_path = keys_dir.join("registry.json");
    
    if !registry_path.exists() {
        return Ok(Vec::new());
    }
    
    let contents = fs::read_to_string(&registry_path)
        .map_err(|e| format!("Failed to read key registry: {}", e))?;
    
    if contents.trim().is_empty() {
        return Ok(Vec::new());
    }
    
    let registry: Vec<String> = serde_json::from_str(&contents)
        .unwrap_or_else(|_| Vec::new());
    
    Ok(registry)
}

/// Add a key pair to the registry
pub fn add_to_registry(key_name: &str) -> Result<(), String> {
    let keys_dir = Path::new("keys");
    if !keys_dir.exists() {
        fs::create_dir_all(keys_dir)
            .map_err(|e| format!("Failed to create keys directory: {}", e))?;
    }
    
    let registry_path = keys_dir.join("registry.json");
    let mut registry = get_key_registry()?;
    
    if !registry.contains(&key_name.to_string()) {
        registry.push(key_name.to_string());
        let registry_json = serde_json::to_string_pretty(&registry)
            .map_err(|e| format!("Failed to serialize registry: {}", e))?;
        fs::write(registry_path, registry_json)
            .map_err(|e| format!("Failed to write registry: {}", e))?;
    }
    
    Ok(())
}

/// Get the latest key pair from registry
pub fn get_latest_key_dir() -> Result<String, String> {
    get_key_registry()?
        .last()
        .cloned()
        .ok_or_else(|| "No keys found in registry. Generate keys first.".to_string())
}

/// Print key information for logging purposes
pub fn print_key_info(key_name: &str) {
    println!("🔑 Using key: {}", key_name);
}