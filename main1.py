from lamport_pqc import LamportSignature

def run_pqc_demo():
    print("=== Post-Quantum Cryptography Demo: Lamport Hash-Based Signatures ===\n")
    
    # 1. Setup and Key Generation
    print("[*] Initializing Lamport Scheme...")
    pqc = LamportSignature()
    
    print("[*] Generating Post-Quantum Key Pairs...")
    _, public_key = pqc.generate_keys()
    print("    -> Success! Keys generated (256 pairs of 256-bit hashes).")
    
    # 2. Signing a Message
    original_message = "Approve transfer of 1000 credits to Bob."
    print(f"\n[*] Original Message: '{original_message}'")
    print("[*] Signing message with the Private Key...")
    
    signature = pqc.sign(original_message)
    print("    -> Success! Message signed. Private key safely destroyed to prevent reuse.")
    
    # 3. Verifying the Valid Message
    print("\n[*] Verifying the signature against the original message...")
    is_valid = pqc.verify(original_message, signature, public_key)
    if is_valid:
        print("    -> [VERIFIED] Signature is authentic. The message is trusted.")
    else:
        print("    -> [FAILED] Signature rejected.")
        
    # 4. Simulating an Attack (Tampering)
    tampered_message = "Approve transfer of 9000 credits to Eve."
    print(f"\n[*] Attacker intercepts and changes message to: '{tampered_message}'")
    print("[*] Verifying the signature against the tampered message...")
    
    is_valid_tampered = pqc.verify(tampered_message, signature, public_key)
    if is_valid_tampered:
        print("    -> [VERIFIED] Signature is authentic.")
    else:
        print("    -> [REJECTED] Tampering detected! Signature does not match the new hash.")

if __name__ == "__main__":
    run_pqc_demo()