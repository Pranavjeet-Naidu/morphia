//! Command handlers for the Morphia CLI

use clap::{Parser, Subcommand};
use std::path::Path;
use crate::crypto::{keygen, encrypt, decrypt, ops};

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
        
        /// Directory to save the keys
        #[arg(short, long, default_value = DEFAULT_KEY_DIR)]
        dir: String,
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
        Commands::Keygen { bits, dir } => {
            println!("Generating key pair with {} bits...", bits);
            let (public_key, private_key) = keygen::generate_keypair(Some(bits));
            
            keygen::save_keys(&public_key, &private_key, &dir)?;
            
            println!("Keys generated successfully!");
            println!("Public key saved to {}/public_key.json", dir);
            println!("Private key saved to {}/private_key.json", dir);
            
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
            
            if let Some(output_path) = output {
                encrypt::save_ciphertext(&ciphertext, &output_path)?;
                println!("Ciphertext saved to {}", output_path);
            }
            
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
            
            if let Some(output_path) = output {
                encrypt::save_ciphertext(&sum, &output_path)?;
                println!("Sum ciphertext saved to {}", output_path);
            }
            
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
            
            println!("\nStep 2: Performing homomorphic addition (without decryption)");
            let encrypted_sum = ops::add(&public_key, &encrypted1, &encrypted2);
            println!("Encrypted sum: {}", encrypted_sum.value);
            
            println!("\nStep 3: Performing homomorphic multiplication by constant {}", constant);
            let encrypted_product = ops::multiply_by_constant(&public_key, &encrypted1, constant);
            println!("Encrypted product: {}", encrypted_product.value);
            
            println!("\nStep 4: Decrypting results to verify correctness");
            let decrypted_sum = decrypt::decrypt(&public_key, &private_key, &encrypted_sum);
            let decrypted_product = decrypt::decrypt(&public_key, &private_key, &encrypted_product);
            
            println!("Expected sum: {} + {} = {}", value1, value2, value1 + value2);
            println!("Decrypted sum: {}", decrypted_sum);
            
            println!("Expected product: {} * {} = {}", value1, constant, value1 * constant);
            println!("Decrypted product: {}", decrypted_product);
            
            if decrypted_sum == value1 + value2 && decrypted_product == value1 * constant {
                println!("\n✅ Homomorphic properties verified successfully!");
            } else {
                println!("\n❌ Homomorphic properties verification failed!");
            }
            
            Ok(())
        },
    }
}