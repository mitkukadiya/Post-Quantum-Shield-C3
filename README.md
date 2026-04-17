# Post-Quantum Cryptography: Hash-Based Signatures

**Course:** Advanced Learning Activity  
**Topic:** Post-Quantum Cryptographic Scheme Demonstration  
**Implementation:** Lamport One-Time Signature (OTS)  

## 1. Project Overview
This repository contains a Python implementation of a post-quantum cryptographic scheme. As quantum computers advance, traditional public-key algorithms based on integer factorization (RSA) and discrete logarithms (ECC) will become vulnerable to Shor's Algorithm. 

To counter this, this project implements **Hash-Based Cryptography**, specifically the **Lamport One-Time Signature**. This scheme is considered quantum-resistant because its security relies entirely on the pre-image resistance of cryptographic hash functions (like SHA-256), which are largely immune to Shor's algorithm and only slightly weakened by Grover's algorithm.

## 2. Theoretical Framework (Lamport OTS)
The Lamport scheme allows a user to sign a single message securely.

* **Key Generation:** The algorithm generates 256 pairs of random 256-bit numbers (the Private Key). It then hashes every single number to create 256 pairs of hashes (the Public Key).
* **Signing:** The message is hashed using SHA-256, resulting in a 256-bit string. For every bit in this hash, the signer reveals one half of their private key pair: if the bit is `0`, they reveal the first number; if `1`, the second. 
* **Verification:** The verifier hashes the original message to get the 256-bit string. They then hash the 256 numbers provided in the signature. If these newly generated hashes match the corresponding halves of the published Public Key, the signature is authentic.

*Note: This is a "One-Time" signature. If a private key is used to sign more than one message, an attacker can deduce missing parts of the private key and forge signatures. Our implementation programmatically deletes the private key from memory immediately after signing to enforce this security rule.*

## 3. Project Structure
* `lamport_pqc.py`: The core cryptographic library containing the key generation, signing, and verification logic.
* `main.py`: The execution script that demonstrates the scheme protecting a transaction and detecting tampering.
* `README.md`: This reference manual.

## 4. Installation and Usage
This project is built using standard Python libraries (`hashlib`, `os`) to ensure maximum compatibility without the need for external C-bindings or mathematical frameworks.

### Prerequisites
* Python 3.x

### Running the Demonstration
Execute the main script from your terminal:
```bash
python main.py
