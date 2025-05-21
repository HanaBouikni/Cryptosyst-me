#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
RSA Cryptosystem Implementation - Version corrigée
"""

import random
import base64
import math
from sympy import isprime

def generate_large_prime(start, end):
    """Génère un grand nombre premier aléatoire dans l'intervalle [start, end]"""
    while True:
        num = random.randint(start, end)
        if isprime(num):
            return num

def generate_rsa_keys():
    """
    Génère une paire de clés RSA avec des nombres premiers plus grands.
    """
    # Génération de nombres premiers plus grands (entre 1000 et 10000)
    prime1 = generate_large_prime(1000, 10000)
    prime2 = generate_large_prime(1000, 10000)
    
    # Vérification que les nombres premiers sont différents
    while prime2 == prime1:
        prime2 = generate_large_prime(1000, 10000)
    
    n = prime1 * prime2
    phi = (prime1 - 1) * (prime2 - 1)
    
    # Choix de e (exposant public)
    e = 65537  # Valeur couramment utilisée en pratique
    if math.gcd(e, phi) != 1:
        e = random.randint(2, phi - 1)
        while math.gcd(e, phi) != 1:
            e = random.randint(2, phi - 1)
    
    # Calcul de d (exposant privé)
    d = mod_inverse(e, phi)
    
    return (e, n), (d, n)

def mod_inverse(a, m):
    """Calcule l'inverse modulaire de a modulo m."""
    g, x, y = extended_gcd(a, m)
    if g != 1:
        raise Exception("L'inverse modulaire n'existe pas")
    else:
        return x % m

def extended_gcd(a, b):
    """Algorithme d'Euclide étendu."""
    if a == 0:
        return b, 0, 1
    else:
        gcd, x1, y1 = extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        return gcd, x, y

def encrypt_rsa(plaintext, public_key):
    """Chiffre un message avec RSA."""
    e, n = public_key
    
    # Vérification que le message n'est pas trop long pour le module n
    if any(ord(char) >= n for char in plaintext):
        raise ValueError("Le message contient des caractères avec des valeurs trop grandes pour le module n")
    
    message_nums = [ord(char) for char in plaintext]
    encrypted_nums = [pow(m, e, n) for m in message_nums]
    encrypted_str = ','.join(map(str, encrypted_nums))
    return base64.b64encode(encrypted_str.encode('utf-8')).decode('utf-8')

def decrypt_rsa(ciphertext, private_key):
    """Déchiffre un message avec RSA."""
    d, n = private_key

    try:
        # Décodage Base64
        decoded_bytes = base64.b64decode(ciphertext)
        decoded_str = decoded_bytes.decode('utf-8')
        
        # Conversion en liste de nombres
        encrypted_nums = [int(num) for num in decoded_str.split(',')]
        
        # Déchiffrement
        decrypted_nums = [pow(c, d, n) for c in encrypted_nums]
        
        # Conversion en caractères avec vérification
        decrypted_message = ""
        for num in decrypted_nums:
            if 0 <= num <= 0x10FFFF:  # Plage valide Unicode
                try:
                    decrypted_message += chr(num)
                except (ValueError, OverflowError):
                    decrypted_message += f"[{num}]"
            else:
                decrypted_message += f"[{num}]"
                
        return decrypted_message

    except Exception as e:
        raise ValueError(f"Échec du déchiffrement: {str(e)}")

def main():
    """Fonction principale."""
    print("=" * 80)
    print("SYSTÈME DE CHIFFREMENT RSA - VERSION CORRIGÉE")
    print("=" * 80)
    
    # Génération des clés RSA
    print("\nGénération des clés RSA...")
    public_key, private_key = generate_rsa_keys()
    e, n = public_key
    d, _ = private_key
    
    print(f"\nClé publique (e, n): ({e}, {n})")
    print(f"Clé privée (d, n): ({d}, {n})")
    
    # Menu principal
    while True:
        print("\n1. Chiffrer un message")
        print("2. Déchiffrer un message")
        print("3. Générer de nouvelles clés")
        print("4. Introduire vos propres clés")
        print("5. Quitter")
        
        choice = input("\nVotre choix (1-5): ").strip()
        
        if choice == "1":
            plaintext = input("\nEntrez le message à chiffrer: ")
            if not plaintext:
                print("Message vide, opération annulée.")
                continue
            
            try:
                ciphertext = encrypt_rsa(plaintext, public_key)
                print(f"\nMessage chiffré (Base64): {ciphertext}")
            except Exception as e:
                print(f"\n❌ Erreur de chiffrement: {e}")
                
        elif choice == "2":
            encoded_ciphertext = input("\nEntrez le message chiffré (Base64): ")
            if not encoded_ciphertext:
                print("Message vide, opération annulée.")
                continue
            
            try:
                decrypted_text = decrypt_rsa(encoded_ciphertext, private_key)
                print(f"\nMessage déchiffré: {decrypted_text}")
            except Exception as e:
                print(f"\n❌ Erreur de déchiffrement: {e}")
                
        elif choice == "3":
            public_key, private_key = generate_rsa_keys()
            e, n = public_key
            d, _ = private_key
            
            print(f"\nNouvelle clé publique (e, n): ({e}, {n})")
            print(f"Nouvelle clé privée (d, n): ({d}, {n})")
            
        elif choice == "4":
            try:
                print("\nIntroduction de vos propres clés RSA:")
                e = int(input("Entrez e (exposant public): "))
                n = int(input("Entrez n (module): "))
                d = int(input("Entrez d (exposant privé): "))
                
                if e <= 1 or n <= 1 or d <= 1:
                    print("\n❌ Valeurs de clés invalides. Les valeurs doivent être supérieures à 1.")
                    continue
                
                public_key = (e, n)
                private_key = (d, n)
                
                print("\n✅ Clés RSA mises à jour avec succès!")
            except ValueError:
                print("\n❌ Erreur: Veuillez entrer des nombres entiers valides.")
                
        elif choice == "5":
            print("\nAu revoir!")
            break
            
        else:
            print("\nOption invalide. Veuillez choisir entre 1 et 5.")
    
    print("\n" + "=" * 80)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nOpération interrompue par l'utilisateur.")
    except Exception as e:
        print(f"\n❌ Erreur: {e}")