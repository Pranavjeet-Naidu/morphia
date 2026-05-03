
# Morphia

A Rust implementation of the Paillier partially homomorphic encryption scheme, featuring secure key management and CLI operations.



## Features

### Core Cryptosystem
- **Key Generation**: Configurable prime sizes (default: 512-bit primes).
- **Secure Prime Generation**: Utilizes the RSA crate.
- **Homomorphic Operations**:
  - Addition of ciphertexts.
  - Multiplication by constants.
- **Semantic Security**: Achieved through random parameter `r` in encryption.



## CLI Tools

### Commands
```bash
# Generate new key pair
cargo run -- keygen [--bits <key-size>]

# Encrypt a number
cargo run -- encrypt --message <number> [--output <output-file>]

# Homomorphically add two ciphertexts
cargo run -- add --cipher1-file <file1> --cipher2-file <file2> [--output <output-file>]

# Decrypt result
cargo run -- decrypt --ciphertext <ciphertext-file>

# Demo the entire process
cargo run -- demo --value1 <number1> --value2 <number2> --constant <number>
```



## Key Management
- **Timestamped Key Directories**: e.g., `keys_20250413_152217`.
- **Master Registry**: Tracks active keys.
- **Automatic Key Selection**: Uses the latest keys by default.
- **Manual Overrides**: Specify keys using the `--dir` parameter.
- **Secure Serialization**: Keys and ciphertexts serialized with JSON.



## Installation
```bash
# Clone repository
git clone https://github.com/yourusername/morphia.git
cd morphia

# Build with Cargo
cargo build --release
```



## Usage

### Basic Workflow

#### 1. Generate Keys
```bash
cargo run -- keygen
```
- Generates public and private keys in a timestamped directory.
- Updates the key registry.

#### 2. Encrypt Values
```bash
cargo run -- encrypt --message 42
```
- Encrypts using the latest key in the registry.
- Saves ciphertext to a timestamped file automatically.
- Use `--output` to specify a custom output file.

#### 3. Homomorphic Addition
```bash
cargo run -- add --cipher1-file ciphertext/20250412_210851.json --cipher2-file ciphertext/20250413_152511.json
```
- Adds two ciphertexts homomorphically.
- Saves the result to a timestamped file in the `ciphertext` directory.
- Optionally, specify output with `--output`.

#### 4. Decrypt Result
```bash
cargo run -- decrypt --ciphertext ciphertext/sum_20250413_161409.json
```
- Uses the latest key to decrypt.
- Automatically handles small value detection for usability.

#### Demo Mode
```bash
cargo run -- demo --value1 5 --value2 7 --constant 3
```
- Demonstrates:
  - `decrypt(add(encrypt(a), encrypt(b))) == a + b`
  - `decrypt(multiply_by_constant(encrypt(a), k)) == a * k`

---

## Technical Details

### Paillier Parameters
| Parameter | Formula       | Description                |
|-----------|---------------|----------------------------|
| `n`       | `p * q`       | Modulus (product of primes)|
| `g`       | `n + 1`       | Generator                 |
| `λ`       | `lcm(p-1, q-1)` | Carmichael function      |
| `μ`       | `λ⁻¹ mod n`   | Decryption coefficient     |

### Homomorphic Properties

Given ciphertexts:
```bash
* E(m₁) = gᵐ¹ · r₁ⁿ mod n²
* E(m₂) = gᵐ² · r₂ⁿ mod n²
```

Addition:
```bash
E(m₁) · E(m₂) mod n² = E(m₁ + m₂ mod n)
```
Scalar Multiplication:
```bash
E(m)ᵏ mod n² = E(k·m mod n) 
```
---

