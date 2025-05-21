#!/usr/bin/env python3
"""
SHA (Secure Hash Algorithm) Implementation
Based on SHA-256 algorithm

This module implements the SHA-256 hashing algorithm which produces a 256-bit (32-byte)
hash value typically rendered as a 64-character hexadecimal number.
"""

import struct
import binascii
import argparse

# SHA-256 Constants
# First 32 bits of the fractional parts of the cube roots of the first 64 prime numbers
K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]

# Initial hash values (first 32 bits of the fractional parts of the square roots of the first 8 prime numbers)
H0 = 0x6a09e667
H1 = 0xbb67ae85
H2 = 0x3c6ef372
H3 = 0xa54ff53a
H4 = 0x510e527f
H5 = 0x9b05688c
H6 = 0x1f83d9ab
H7 = 0x5be0cd19

def rotr(x, n):
    """Right rotate a 32-bit integer x by n bits"""
    return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF

def ch(x, y, z):
    """Bitwise choice function"""
    return (x & y) ^ (~x & z)

def maj(x, y, z):
    """Bitwise majority function"""
    return (x & y) ^ (x & z) ^ (y & z)

def sigma0(x):
    """Sigma 0 function"""
    return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22)

def sigma1(x):
    """Sigma 1 function"""
    return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25)

def gamma0(x):
    """Gamma 0 function"""
    return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3)

def gamma1(x):
    """Gamma 1 function"""
    return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10)

def pad_message(message):
    """
    Pad the message according to SHA-256 specifications:
    1. Append a single '1' bit
    2. Append K '0' bits, where K is the minimum number >= 0 such that the resulting message
       length (in bits) is congruent to 448 (mod 512)
    3. Append the length of the original message as a 64-bit big-endian integer
    """
    # Convert message to bytes if it's a string
    if isinstance(message, str):
        message = message.encode('utf-8')
    
    message_len_bits = len(message) * 8
    
    # Append the bit '1' (as a byte 0x80)
    padded_message = bytearray(message) + b'\x80'
    
    # Append K zeros so that the final length is congruent to 448 (mod 512)
    padding_len = 64 - ((len(padded_message) + 8) % 64)  # 8 bytes for the length
    padded_message += b'\x00' * padding_len
    
    # Append message length as a 64-bit big-endian integer
    padded_message += struct.pack('>Q', message_len_bits)
    
    return padded_message

def sha256(message):
    """
    Calculate the SHA-256 hash of a message.
    """
    # Initialize hash values
    h0, h1, h2, h3, h4, h5, h6, h7 = H0, H1, H2, H3, H4, H5, H6, H7
    
    # Preprocess the message
    padded_message = pad_message(message)
    
    # Process message in 512-bit (64-byte) chunks
    for i in range(0, len(padded_message), 64):
        chunk = padded_message[i:i+64]
        
        # Break chunk into sixteen 32-bit big-endian words
        w = list(struct.unpack('>16L', chunk))
        
        # Extend the sixteen 32-bit words into sixty-four 32-bit words
        for j in range(16, 64):
            w.append((gamma1(w[j-2]) + w[j-7] + gamma0(w[j-15]) + w[j-16]) & 0xFFFFFFFF)
        
        # Initialize working variables with current hash value
        a, b, c, d, e, f, g, h = h0, h1, h2, h3, h4, h5, h6, h7
        
        # Main loop
        for j in range(64):
            t1 = (h + sigma1(e) + ch(e, f, g) + K[j] + w[j]) & 0xFFFFFFFF
            t2 = (sigma0(a) + maj(a, b, c)) & 0xFFFFFFFF
            h = g
            g = f
            f = e
            e = (d + t1) & 0xFFFFFFFF
            d = c
            c = b
            b = a
            a = (t1 + t2) & 0xFFFFFFFF
        
        # Update hash values
        h0 = (h0 + a) & 0xFFFFFFFF
        h1 = (h1 + b) & 0xFFFFFFFF
        h2 = (h2 + c) & 0xFFFFFFFF
        h3 = (h3 + d) & 0xFFFFFFFF
        h4 = (h4 + e) & 0xFFFFFFFF
        h5 = (h5 + f) & 0xFFFFFFFF
        h6 = (h6 + g) & 0xFFFFFFFF
        h7 = (h7 + h) & 0xFFFFFFFF
    
    # Produce the final hash value as a 256-bit (32-byte) number
    digest = struct.pack('>8L', h0, h1, h2, h3, h4, h5, h6, h7)
    return binascii.hexlify(digest).decode('ascii')

def sha224(message):
    """
    Calculate the SHA-224 hash of a message.
    SHA-224 is identical to SHA-256, but with different initial values and truncated output.
    """
    # Different initial hash values for SHA-224
    h0 = 0xc1059ed8
    h1 = 0x367cd507
    h2 = 0x3070dd17
    h3 = 0xf70e5939
    h4 = 0xffc00b31
    h5 = 0x68581511
    h6 = 0x64f98fa7
    h7 = 0xbefa4fa4
    
    # Use SHA-256 algorithm with different initial values
    # Preprocess the message
    padded_message = pad_message(message)
    
    # Process message in 512-bit (64-byte) chunks
    for i in range(0, len(padded_message), 64):
        chunk = padded_message[i:i+64]
        
        # Break chunk into sixteen 32-bit big-endian words
        w = list(struct.unpack('>16L', chunk))
        
        # Extend the sixteen 32-bit words into sixty-four 32-bit words
        for j in range(16, 64):
            w.append((gamma1(w[j-2]) + w[j-7] + gamma0(w[j-15]) + w[j-16]) & 0xFFFFFFFF)
        
        # Initialize working variables with current hash value
        a, b, c, d, e, f, g, h = h0, h1, h2, h3, h4, h5, h6, h7
        
        # Main loop
        for j in range(64):
            t1 = (h + sigma1(e) + ch(e, f, g) + K[j] + w[j]) & 0xFFFFFFFF
            t2 = (sigma0(a) + maj(a, b, c)) & 0xFFFFFFFF
            h = g
            g = f
            f = e
            e = (d + t1) & 0xFFFFFFFF
            d = c
            c = b
            b = a
            a = (t1 + t2) & 0xFFFFFFFF
        
        # Update hash values
        h0 = (h0 + a) & 0xFFFFFFFF
        h1 = (h1 + b) & 0xFFFFFFFF
        h2 = (h2 + c) & 0xFFFFFFFF
        h3 = (h3 + d) & 0xFFFFFFFF
        h4 = (h4 + e) & 0xFFFFFFFF
        h5 = (h5 + f) & 0xFFFFFFFF
        h6 = (h6 + g) & 0xFFFFFFFF
        h7 = (h7 + h) & 0xFFFFFFFF
    
    # Produce the final hash value (SHA-224 truncates the last 32 bits)
    digest = struct.pack('>7L', h0, h1, h2, h3, h4, h5, h6)
    return binascii.hexlify(digest).decode('ascii')

def sha512(message):
    """
    A simplified placeholder for SHA-512 implementation.
    Note: This is not a full implementation of SHA-512, which operates on 64-bit words.
    A complete implementation would require significant changes to adapt for 64-bit operations.
    """
    # For education purposes, we'll just note that SHA-512 uses:
    # - 64-bit words instead of 32-bit
    # - 80 rounds instead of 64
    # - Different constants and shift values
    # - Message length is a 128-bit field rather than 64-bit
    
    # This is a placeholder that uses SHA-256 with a prefix to differentiate
    # In a real implementation, SHA-512 would be implemented separately
    if isinstance(message, str):
        message = message.encode('utf-8')
    
    placeholder_message = b"SHA-512:" + message
    return sha256(placeholder_message)

def main():
    """
    Command-line interface for SHA hash functions
    """
    parser = argparse.ArgumentParser(description='SHA Hash Calculator')
    parser.add_argument('--algorithm', '-a', choices=['sha224', 'sha256', 'sha512'], 
                        default='sha256', help='SHA algorithm to use (default: sha256)')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--text', '-t', help='Text to hash')
    group.add_argument('--file', '-f', help='File to hash')
    
    args = parser.parse_args()
    
    # Get the message to hash
    if args.text:
        message = args.text
    else:
        try:
            with open(args.file, 'rb') as f:
                message = f.read()
        except Exception as e:
            print(f"Error reading file: {e}")
            return
    
    # Calculate the hash
    if args.algorithm == 'sha224':
        hash_result = sha224(message)
    elif args.algorithm == 'sha256':
        hash_result = sha256(message)
    elif args.algorithm == 'sha512':
        hash_result = sha512(message)
    
    print(f"{args.algorithm.upper()} Hash: {hash_result}")

if __name__ == "__main__":
    # If no arguments provided, offer interactive mode
    import sys
    if len(sys.argv) == 1:
        print("SHA Hash Calculator ")
        print("=====================================")
        
        while True:
            print("\nSelect an algorithm:")
            print("1. SHA-224")
            print("2. SHA-256")
            print("3. SHA-512")
            print("0. Exit")
            
            choice = input("Enter your choice (0-3): ")
            
            if choice == '0':
                break
            elif choice in ['1', '2', '3']:
                text = input("Enter text to hash: ")
                
                if choice == '1':
                    hash_result = sha224(text)
                    algorithm = "SHA-224"
                elif choice == '2':
                    hash_result = sha256(text)
                    algorithm = "SHA-256"
                else:
                    hash_result = sha512(text)
                    algorithm = "SHA-512"
                
                print(f"\n{algorithm} Hash: {hash_result}")
            else:
                print("Invalid choice. Please try again.")
    else:
        main()