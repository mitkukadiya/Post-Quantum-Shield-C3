import hashlib
import os

class LamportSignature:
    def __init__(self):
        """
        Initializes the Lamport One-Time Signature scheme.
        We use SHA-256, which produces a 256-bit hash. 
        Therefore, our keys need 256 pairs of random strings.
        """
        self.hash_length_bits = 256
        self.private_key = []
        self.public_key = []

    def generate_keys(self):
        """
        Generates a private and public key pair.
        Private Key: 256 pairs of 32-byte random numbers.
        Public Key: The SHA-256 hash of each corresponding private key number.
        """
        self.private_key = []
        self.public_key = []
        
        for _ in range(self.hash_length_bits):
            # Generate two random 32-byte strings for the private key
            sk_0 = os.urandom(32)
            sk_1 = os.urandom(32)
            self.private_key.append((sk_0, sk_1))
            
            # Hash them to create the public key components
            pk_0 = hashlib.sha256(sk_0).digest()
            pk_1 = hashlib.sha256(sk_1).digest()
            self.public_key.append((pk_0, pk_1))
            
        return self.private_key, self.public_key

    def _get_message_bits(self, message):
        """Helper function to hash the message and convert it to a binary string."""
        msg_hash = hashlib.sha256(message.encode('utf-8')).digest()
        # Convert each byte to an 8-bit binary string and concatenate
        return ''.join(f'{byte:08b}' for byte in msg_hash)

    def sign(self, message):
        """
        Signs a message.
        For each bit in the message hash, we reveal one half of the private key pair.
        If the bit is 0, reveal sk_0. If the bit is 1, reveal sk_1.
        """
        if not self.private_key:
            raise ValueError("Keys must be generated before signing.")
            
        msg_bits = self._get_message_bits(message)
        signature = []
        
        for i, bit in enumerate(msg_bits):
            if bit == '0':
                signature.append(self.private_key[i][0])
            else:
                signature.append(self.private_key[i][1])
                
        # Security Warning for Lamport: The private key must NEVER be used again.
        self.private_key = [] 
        
        return signature

    def verify(self, message, signature, public_key):
        """
        Verifies a signature against the public key.
        Hashes the message to get the bit sequence, then hashes the provided 
        signature blocks and checks if they match the expected public key blocks.
        """
        msg_bits = self._get_message_bits(message)
        
        if len(signature) != self.hash_length_bits:
            return False
            
        for i, bit in enumerate(msg_bits):
            # Hash the part of the signature provided by the signer
            sig_hash = hashlib.sha256(signature[i]).digest()
            
            # Compare it to the corresponding part of the public key
            expected_pk = public_key[i][0] if bit == '0' else public_key[i][1]
            
            if sig_hash != expected_pk:
                return False
                
        return True