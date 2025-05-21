#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
RC4 (Rivest Cipher 4) Implementation
Developed by Ron Rivest in 1987, RC4 is a stream cipher used in protocols like WEP and WPA.
"""
import argparse
import sys


def initialize_permutation(key):
    """
    Initialise la permutation S en fonction de la clé.
    
    Args:
        key: La clé sous forme de bytes
        
    Returns:
        La permutation S initialisée (un tableau de 256 entrées)
    """
    # Initialisation du tableau S
    S = list(range(256))
    
    # Mélange de S en fonction de la clé
    j = 0
    key_length = len(key)
    
    for i in range(256):
        j = (j + S[i] + key[i % key_length]) % 256
        # Permuter S[i] et S[j]
        S[i], S[j] = S[j], S[i]
        
    return S


def generate_keystream(S, data_length):
    """
    Génère un flux de clé pseudo-aléatoire.
    
    Args:
        S: La permutation initialisée
        data_length: Longueur des données à chiffrer/déchiffrer
        
    Returns:
        Le flux de clé (keystream) de longueur data_length
    """
    i = 0
    j = 0
    keystream = []
    
    for _ in range(data_length):
        # Génération du flux
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        
        # Permuter S[i] et S[j]
        S[i], S[j] = S[j], S[i]
        
        # Génération de l'octet du flux
        t = (S[i] + S[j]) % 256
        k = S[t]
        keystream.append(k)
        
    return keystream


def rc4_encrypt_decrypt(key, data):
    """
    Chiffre ou déchiffre des données avec RC4 (opération symétrique).
    
    Args:
        key: La clé sous forme de bytes
        data: Les données à chiffrer/déchiffrer sous forme de bytes
        
    Returns:
        Les données chiffrées/déchiffrées
    """
    # Initialisation de la permutation
    S = initialize_permutation(key)
    
    # Génération du flux de clé
    keystream = generate_keystream(S, len(data))
    
    # Chiffrement/déchiffrement par XOR
    result = bytearray()
    for i in range(len(data)):
        # XOR entre l'octet de données et l'octet du flux de clé
        result.append(data[i] ^ keystream[i])
        
    return bytes(result)


def string_to_bytes(s):
    """Convertit une chaîne de caractères en bytes."""
    return s.encode('utf-8')


def bytes_to_string(b):
    """Convertit des bytes en chaîne de caractères, en ignorant les caractères non-affichables."""
    try:
        return b.decode('utf-8')
    except UnicodeDecodeError:
        # Pour afficher les données binaires si non décodables en UTF-8
        return b.hex()


def hex_to_bytes(hex_str):
    """Convertit une chaîne hexadécimale en bytes."""
    return bytes.fromhex(hex_str)


def print_banner():
    """Affiche une bannière pour le programme RC4."""
    banner = """
    +---------------------------------------------------+
    |                   RC4 CRYPTOSYSTEM                |
    |            (Rivest Cipher 4 / Ron's Code)         |
    +---------------------------------------------------+
    |  Développé par Ron Rivest en 1987                 |
    |  Utilisé dans: WEP, WPA, SSL/TLS, Oracle SQL      |
    +---------------------------------------------------+
    """
    print(banner)


def main():
    # Affichage de la bannière
    print_banner()
    parser = argparse.ArgumentParser(description='RC4 - Chiffrement et déchiffrement')
    parser.add_argument('--key', '-k', help='Clé de chiffrement')
    parser.add_argument('--mode', '-m', choices=['encrypt', 'decrypt'], default='encrypt',
                        help='Mode: encrypt ou decrypt (par défaut: encrypt)')
    parser.add_argument('--text', '-t', help='Texte à chiffrer/déchiffrer')
    parser.add_argument('--hex', '-x', action='store_true', 
                        help='Indique que l\'entrée/sortie est en format hexadécimal')
    parser.add_argument('--file', '-f', help='Fichier à chiffrer/déchiffrer')
    parser.add_argument('--output', '-o', help='Fichier de sortie')
    
    args = parser.parse_args()
    
    # Demande interactive si la clé n'est pas fournie
    if not args.key:
        args.key = input("Entrez la clé de chiffrement: ")
    
    # Conversion de la clé en bytes
    key = string_to_bytes(args.key)
    
    # Détermination des données d'entrée
    if args.file:
        try:
            with open(args.file, 'rb') as f:
                data = f.read()
        except FileNotFoundError:
            print(f"Erreur: Le fichier '{args.file}' n'existe pas.")
            return
    elif args.text:
        if args.hex:
            try:
                data = hex_to_bytes(args.text)
            except ValueError:
                print("Erreur: Format hexadécimal invalide.")
                return
        else:
            data = string_to_bytes(args.text)
    else:
        # Mode interactif si aucun texte ou fichier n'est fourni
        user_input = input("Entrez le texte à " + ("déchiffrer" if args.mode == "decrypt" else "chiffrer") + ": ")
        if args.hex:
            try:
                data = hex_to_bytes(user_input)
            except ValueError:
                print("Erreur: Format hexadécimal invalide.")
                return
        else:
            data = string_to_bytes(user_input)
    
    # Application de RC4
    result = rc4_encrypt_decrypt(key, data)
    
    # Gestion de la sortie
    if args.output:
        with open(args.output, 'wb') as f:
            f.write(result)
        print(f"Résultat écrit dans le fichier '{args.output}'")
    else:
        if args.hex:
            hex_result = result.hex()
            print(f"Résultat (hex): {hex_result}")
        else:
            try:
                output = result.decode('utf-8')
                print(f"Résultat: {output}")
            except UnicodeDecodeError:
                print(f"Résultat (non décodable en UTF-8, affichage en hex): {result.hex()}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nOpération annulée par l'utilisateur.")
        sys.exit(1)