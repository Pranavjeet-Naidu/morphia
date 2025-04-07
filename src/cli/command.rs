//! Command handlers for the Morphia CLI

use clap::{Parser, Subcommand};
use std::path::Path;
use crate::crypto::{keygen, encrypt, decrypt, ops};
use chrono::Utc;
use num_bigint::BigUint;
use num_traits::ToPrimitive; 

/// Default directory for storing keys
const DEFAULT_KEY_DIR: &str = "keys";

/// Command-line arguments for the Morphia application
#[derive(Parser, Debug)]
#[command(author, version, about = "A homomorphic encryption demo using the Paillier cryptosystem")]
pub struct Cli {
    #[command(subcommand)]
    command: Commands,
}

/// Subcommands for the Morphia application
#[derive(Subcommand, Debug)]
enum Commands {
    /// Generate a new key pair
    Keygen {
        /// Key size in bits (must be divisible by 2)
        #[arg(short, long, default_value = "512")]
        bits: usize,
        
        /// Base directory to save the keys
        #[arg(short, long, default_value = DEFAULT_KEY_DIR)]
        dir: String,
        
        /// Use timestamp for key folder name
        #[arg(short, long, default_value = "true")]
        timestamp: bool,
    },
    
    /// Encrypt a message
    Encrypt {
        /// Message to encrypt
        #[arg(short, long)]
        message: u64,
        
        /// Directory containing the public key
        #[arg(short, long, default_value = DEFAULT_KEY_DIR)]
        dir: String,
        
        /// Output file for the ciphertext
        #[arg(short, long)]
        output: Option<String>,
    },
    
    /// Decrypt a ciphertext
    Decrypt {
        /// Path to the ciphertext file
        #[arg(short, long)]
        ciphertext: Option<String>,
        
        /// Ciphertext value (if not using a file)
        #[arg(short, long)]
        value: Option<String>,
        
        /// Directory containing the keys
        #[arg(short, long, default_value = DEFAULT_KEY_DIR)]
        dir: String,
    },
    
    /// Homomorphically add two ciphertexts
    Add {
        /// Path to the first ciphertext file
        #[arg(long)]
        cipher1_file: Option<String>,
        
        /// First ciphertext value (if not using a file)
        #[arg(long)]
        cipher1: Option<String>,
        
        /// Path to the second ciphertext file
        #[arg(long)]
        cipher2_file: Option<String>,
        
        /// Second ciphertext value (if not using a file)
        #[arg(long)]
        cipher2: Option<String>,
        
        /// Directory containing the public key
        #[arg(short, long, default_value = DEFAULT_KEY_DIR)]
        dir: String,
        
        /// Output file for the result
        #[arg(short, long)]
        output: Option<String>,
    },
    
    /// Run a demonstration of homomorphic properties
    Demo {
        /// First value to encrypt
        #[arg(long, default_value = "10")]
        value1: u64,
        
        /// Second value to encrypt
        #[arg(long, default_value = "20")]
        value2: u64,
        
        /// Constant for homomorphic multiplication
        #[arg(long, default_value = "3")]
        constant: u64,
        
        /// Directory containing the keys
        #[arg(short, long, default_value = DEFAULT_KEY_DIR)]
        dir: String,
    },
}

/// Run the CLI
pub fn run() -> Result<(), String> {
    let cli = Cli::parse();
    
    match cli.command {
        Commands::Keygen { bits, dir, timestamp } => {
            println!("Generating key pair with {} bits...", bits);
            let (public_key, private_key) = keygen::generate_keypair(Some(bits));
            
            // Create a timestamped key directory if requested
            let key_dir = if timestamp {
                let timestamp = Utc::now().format("%Y%m%d_%H%M%S").to_string();
                format!("{}/keys_{}", dir, timestamp)
            } else {
                dir.clone()
            };
            
            // Create the directory structure
            std::fs::create_dir_all(&key_dir)
                .map_err(|e| format!("Failed to create key directory: {}", e))?;
            
            keygen::save_keys(&public_key, &private_key, &key_dir)?;
            
            println!("Keys generated successfully!");
            println!("Public key saved to {}/public_key.json", key_dir);
            println!("Private key saved to {}/private_key.json", key_dir);
            
            // Print some key details for demo purposes
            println!("\nPublic Key Details:");
            println!("n = {} ({})", public_key.n, public_key.n.bits());
            println!("g = {} ({})", public_key.g, public_key.g.bits());
            
            println!("\nPrivate Key Details:");
            println!("lambda = {} ({})", private_key.lambda, private_key.lambda.bits());
            println!("mu = {} ({})", private_key.mu, private_key.mu.bits());
            
            Ok(())
        },
        
        Commands::Encrypt { message, dir, output } => {
            println!("Loading public key from {}...", dir);
            let public_key = keygen::load_public_key(&dir)?;
            
            println!("Encrypting message: {}", message);
            let ciphertext = encrypt::encrypt(&public_key, message);
            
            println!("Ciphertext: {}", ciphertext.value);
            
            // Save to specified output if provided
            if let Some(output_path) = output {
                encrypt::save_ciphertext(&ciphertext, &output_path)?;
                println!("Ciphertext saved to {}", output_path);
            }
            
            // Always save to ciphertext directory with timestamp
            let timestamp = Utc::now().format("%Y%m%d_%H%M%S").to_string();
            let auto_path = format!("ciphertext/{}.json", timestamp);
            
            // Create ciphertext directory if it doesn't exist
            std::fs::create_dir_all("ciphertext")
                .map_err(|e| format!("Failed to create ciphertext directory: {}", e))?;
            
            encrypt::save_ciphertext(&ciphertext, &auto_path)?;
            println!("Ciphertext automatically saved to {}", auto_path);
            
            Ok(())
        },
        
        Commands::Decrypt { ciphertext, value, dir } => {
            println!("Loading keys from {}...", dir);
            let public_key = keygen::load_public_key(&dir)?;
            let private_key = keygen::load_private_key(&dir)?;
            
            let cipher = if let Some(path) = ciphertext {
                println!("Loading ciphertext from {}...", path);
                encrypt::load_ciphertext(&path)?
            } else if let Some(val) = value {
                println!("Using provided ciphertext value...");
                let cipher_val = val.parse::<u128>().map_err(|_| "Invalid ciphertext value")?;
                encrypt::Ciphertext { value: cipher_val.into() }
            } else {
                return Err("Either --ciphertext or --value must be provided".to_string());
            };
            
            println!("Decrypting ciphertext...");
            let plaintext = decrypt::decrypt(&public_key, &private_key, &cipher);
            
            println!("Decrypted value: {}", plaintext);
            
            // Try to convert to u64 for display if possible
            match plaintext.to_u64() {
                Some(value) => println!("Decrypted value (as u64): {}", value),
                None => println!("(Note: Value is too large to represent as u64)")
            }
            
            Ok(())
        },
        
        Commands::Add { cipher1_file, cipher1, cipher2_file, cipher2, dir, output } => {
            println!("Loading public key from {}...", dir);
            let public_key = keygen::load_public_key(&dir)?;
            
            let c1 = if let Some(path) = cipher1_file {
                println!("Loading first ciphertext from {}...", path);
                encrypt::load_ciphertext(&path)?
            } else if let Some(val) = cipher1 {
                println!("Using provided first ciphertext value...");
                let cipher_val = val.parse::<u128>().map_err(|_| "Invalid ciphertext value")?;
                encrypt::Ciphertext { value: cipher_val.into() }
            } else {
                return Err("Either --cipher1_file or --cipher1 must be provided".to_string());
            };
            
            let c2 = if let Some(path) = cipher2_file {
                println!("Loading second ciphertext from {}...", path);
                encrypt::load_ciphertext(&path)?
            } else if let Some(val) = cipher2 {
                println!("Using provided second ciphertext value...");
                let cipher_val = val.parse::<u128>().map_err(|_| "Invalid ciphertext value")?;
                encrypt::Ciphertext { value: cipher_val.into() }
            } else {
                return Err("Either --cipher2_file or --cipher2 must be provided".to_string());
            };
            
            println!("Performing homomorphic addition...");
            let sum = ops::add(&public_key, &c1, &c2);
            
            println!("Sum ciphertext: {}", sum.value);
            
            // Save to specified output if provided
            if let Some(output_path) = output {
                encrypt::save_ciphertext(&sum, &output_path)?;
                println!("Sum ciphertext saved to {}", output_path);
            }
            
            // Always save to ciphertext directory with timestamp
            let timestamp = Utc::now().format("%Y%m%d_%H%M%S").to_string();
            let auto_path = format!("ciphertext/sum_{}.json", timestamp);
            
            // Create ciphertext directory if it doesn't exist
            std::fs::create_dir_all("ciphertext")
                .map_err(|e| format!("Failed to create ciphertext directory: {}", e))?;
            
            encrypt::save_ciphertext(&sum, &auto_path)?;
            println!("Sum ciphertext automatically saved to {}", auto_path);
            
            Ok(())
        },
        
        Commands::Demo { value1, value2, constant, dir } => {
            println!("Running homomorphic encryption demonstration...");
            
            if !Path::new(&dir).exists() {
                println!("Generating new keys for demo...");
                let (public_key, private_key) = keygen::generate_keypair(Some(512));
                keygen::save_keys(&public_key, &private_key, &dir)?;
            }
            
            let public_key = keygen::load_public_key(&dir)?;
            let private_key = keygen::load_private_key(&dir)?;
            
            println!("\nStep 1: Encrypting values {} and {}", value1, value2);
            let encrypted1 = encrypt::encrypt(&public_key, value1);
            let encrypted2 = encrypt::encrypt(&public_key, value2);
            println!("Encrypted {} to: {}", value1, encrypted1.value);
            println!("Encrypted {} to: {}", value2, encrypted2.value);
            
            // Save encrypted values
            let timestamp = Utc::now().format("%Y%m%d_%H%M%S").to_string();
            let dir_path = "ciphertext";
            
            // Create directory if it doesn't exist
            std::fs::create_dir_all(dir_path)
                .map_err(|e| format!("Failed to create ciphertext directory: {}", e))?;
                
            let path1 = format!("{}/demo_val1_{}.json", dir_path, timestamp);
            let path2 = format!("{}/demo_val2_{}.json", dir_path, timestamp);
            encrypt::save_ciphertext(&encrypted1, &path1)?;
            encrypt::save_ciphertext(&encrypted2, &path2)?;
            println!("Demo values saved to {} and {}", path1, path2);
            
            println!("\nStep 2: Performing homomorphic addition (without decryption)");
            let encrypted_sum = ops::add(&public_key, &encrypted1, &encrypted2);
            println!("Encrypted sum: {}", encrypted_sum.value);
            
            let path_sum = format!("{}/demo_sum_{}.json", dir_path, timestamp);
            encrypt::save_ciphertext(&encrypted_sum, &path_sum)?;
            println!("Demo sum saved to {}", path_sum);
            
            println!("\nStep 3: Performing homomorphic multiplication by constant {}", constant);
            let encrypted_product = ops::multiply_by_constant(&public_key, &encrypted1, constant);
            println!("Encrypted product: {}", encrypted_product.value);
            
            let path_prod = format!("{}/demo_prod_{}.json", dir_path, timestamp);
            encrypt::save_ciphertext(&encrypted_product, &path_prod)?;
            println!("Demo product saved to {}", path_prod);
            
            println!("\nStep 4: Decrypting results to verify correctness");
            let decrypted_sum = decrypt::decrypt(&public_key, &private_key, &encrypted_sum);
            let decrypted_product = decrypt::decrypt(&public_key, &private_key, &encrypted_product);
            
            let expected_sum = BigUint::from(value1 + value2);
            let expected_product = BigUint::from(value1 * constant);
            
            println!("Expected sum: {} + {} = {}", value1, value2, expected_sum);
            println!("Decrypted sum: {}", decrypted_sum);
            
            println!("Expected product: {} * {} = {}", value1, constant, expected_product);
            println!("Decrypted product: {}", decrypted_product);
            
            if decrypted_sum == expected_sum && decrypted_product == expected_product {
                println!("\n✅ Homomorphic properties verified successfully!");
            } else {
                println!("\n❌ Homomorphic properties verification failed!");
                
                // Show detailed comparison
                println!("\nDetailed comparison:");
                println!("Sum: {} vs {}", expected_sum, decrypted_sum);
                println!("Product: {} vs {}", expected_product, decrypted_product);
            }
            
            Ok(())
        },
    }
}