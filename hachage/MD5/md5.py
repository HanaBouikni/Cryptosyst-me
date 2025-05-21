#!/usr/bin/env python3
'''
Implémentation de l'algorithme MD5 basée sur le RFC 1321
'''

import struct
import math
import argparse
import sys
from typing import List, Tuple

# Constantes pour MD5
# Décalages par tour (16 opérations par tour)
SHIFTS = [
    # Tour 1
    [7, 12, 17, 22] * 4,
    # Tour 2
    [5, 9, 14, 20] * 4,
    # Tour 3
    [4, 11, 16, 23] * 4,
    # Tour 4
    [6, 10, 15, 21] * 4
]
SHIFTS = [item for sublist in SHIFTS for item in sublist]  # Aplatir la liste

# Tableau des constantes Ti = floor(2^32 * abs(sin(i))) pour i de 1 à 64
T = [
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
    0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
    0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
    0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
    0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
]

# Fonctions auxiliaires pour chaque tour
def F(x: int, y: int, z: int) -> int:
    return (x & y) | (~x & z)

def G(x: int, y: int, z: int) -> int:
    return (x & z) | (y & ~z)

def H(x: int, y: int, z: int) -> int:
    return x ^ y ^ z

def I(x: int, y: int, z: int) -> int:
    return y ^ (x | ~z)

# Fonctions de rotation à gauche
def left_rotate(x: int, n: int) -> int:
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

def pad_message(message: bytes) -> bytes:
    """
    Ajoute le padding au message selon les règles MD5:
    1. Ajouter un bit '1' à la fin
    2. Ajouter des '0' pour que la longueur soit congrue à 448 modulo 512
    3. Ajouter la longueur originale du message sur 64 bits
    """
    # Longueur originale en bits
    orig_bit_len = len(message) * 8
    
    # Ajouter le bit '1' suivi de zéros
    message += b'\x80'
    
    # Ajouter des zéros jusqu'à ce que la longueur soit congrue à 448 modulo 512
    while (len(message) * 8) % 512 != 448:
        message += b'\x00'
    
    # Ajouter la longueur originale en little endian (64 bits)
    message += struct.pack('<Q', orig_bit_len)
    
    return message

def md5(message: bytes) -> bytes:
    """
    Calcule l'empreinte MD5 d'un message
    """
    # Initialisation des registres (en little endian)
    a0, b0, c0, d0 = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476
    
    # Préparation du message (padding)
    padded_message = pad_message(message)
    
    # Traitement des blocs de 512 bits (64 octets)
    for offset in range(0, len(padded_message), 64):
        block = padded_message[offset:offset+64]
        
        # Diviser le bloc en 16 mots de 32 bits (4 octets)
        X = list(struct.unpack('<16I', block))
        
        # Copier les valeurs des registres
        A, B, C, D = a0, b0, c0, d0
        
        # Boucle principale avec 4 tours de 16 opérations
        for i in range(64):
            if i < 16:
                # Tour 1
                func, k = F, i
            elif i < 32:
                # Tour 2
                func, k = G, (5 * i + 1) % 16
            elif i < 48:
                # Tour 3
                func, k = H, (3 * i + 5) % 16
            else:
                # Tour 4
                func, k = I, (7 * i) % 16
            
            temp = D
            D = C
            C = B
            B = (B + left_rotate((A + func(B, C, D) + X[k] + T[i]) & 0xFFFFFFFF, SHIFTS[i])) & 0xFFFFFFFF
            A = temp
        
        # Ajouter le résultat au bloc précédent
        a0 = (a0 + A) & 0xFFFFFFFF
        b0 = (b0 + B) & 0xFFFFFFFF
        c0 = (c0 + C) & 0xFFFFFFFF
        d0 = (d0 + D) & 0xFFFFFFFF
    
    # Concaténer les registres pour former le résultat final (en little endian)
    digest = struct.pack('<4I', a0, b0, c0, d0)
    return digest

def md5_hexdigest(message: bytes) -> str:
    """
    Retourne l'empreinte MD5 sous forme hexadécimale
    """
    return ''.join(f'{b:02x}' for b in md5(message))

def interactive_mode():
    """
    Mode interactif avec interface améliorée
    """
    print("MD5 Hash Calculator")
    print("=" * 40)
    
    while True:
        print("\nOptions disponibles:")
        print("1. Hacher un texte")
        print("2. Hacher un fichier")
        print("3. Comparer deux hachages")
        print("0. Quitter")
        
        choice = input("\nEntrez votre choix (0-3): ").strip()
        
        if choice == '0':
            print("Au revoir!")
            break
        elif choice == '1':
            text = input("\nEntrez le texte à hacher: ")
            if text:
                message = text.encode('utf-8')
                hash_result = md5_hexdigest(message)
                print(f"\nTexte: {text}")
                print(f"MD5: {hash_result}")
                print(f"Longueur: {len(hash_result)} caractères")
            else:
                print("Aucun texte saisi.")
                
        elif choice == '2':
            filename = input("\nEntrez le nom du fichier: ").strip()
            if filename:
                try:
                    with open(filename, 'rb') as f:
                        message = f.read()
                        hash_result = md5_hexdigest(message)
                        file_size = len(message)
                        print(f"\nFichier: {filename}")
                        print(f"Taille: {file_size} octets")
                        print(f"MD5: {hash_result}")
                except FileNotFoundError:
                    print(f"Erreur: Le fichier '{filename}' n'existe pas.")
                except Exception as e:
                    print(f"Erreur lors de la lecture du fichier: {e}")
            else:
                print("Aucun nom de fichier saisi.")
                
        elif choice == '3':
            print("\nComparaison de hachages MD5")
            hash1 = input("Premier hachage MD5: ").strip().lower()
            hash2 = input("Deuxième hachage MD5: ").strip().lower()
            
            if hash1 and hash2:
                if len(hash1) != 32 or len(hash2) != 32:
                    print("Attention: Un hachage MD5 doit faire exactement 32 caractères hexadécimaux.")
                
                if hash1 == hash2:
                    print("✅ Les hachages sont IDENTIQUES")
                else:
                    print("❌ Les hachages sont DIFFÉRENTS")
                    # Afficher les différences caractère par caractère
                    print("\nAnalyse des différences:")
                    for i, (c1, c2) in enumerate(zip(hash1, hash2)):
                        if c1 != c2:
                            print(f"Position {i+1}: '{c1}' ≠ '{c2}'")
            else:
                print("Veuillez saisir les deux hachages.")
                
        else:
            print("Choix invalide. Veuillez réessayer.")

def main():
    """
    Interface en ligne de commande améliorée
    """
    parser = argparse.ArgumentParser(
        description='Calculateur d\'empreinte MD5',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Exemples d'utilisation:
  %(prog)s --text "Hello World"
  %(prog)s --file document.txt
  %(prog)s --text "test" --verbose
        '''
    )
    
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--text', '-t', help='Texte à hacher')
    group.add_argument('--file', '-f', help='Fichier à hacher')
    parser.add_argument('--verbose', '-v', action='store_true', 
                        help='Affichage détaillé')
    
    args = parser.parse_args()
    
    # Si aucun argument, lancer le mode interactif
    if len(sys.argv) == 1:
        interactive_mode()
        return
    
    # Traitement des arguments en ligne de commande
    if args.text:
        message = args.text.encode('utf-8')
        hash_result = md5_hexdigest(message)
        
        if args.verbose:
            print("=" * 50)
            print("CALCULATEUR MD5")
            print("=" * 50)
            print(f"Texte d'entrée: {args.text}")
            print(f"Longueur: {len(args.text)} caractères")
            print(f"Taille en octets: {len(message)} octets")
            print("-" * 50)
            print(f"Empreinte MD5: {hash_result}")
            print(f"Longueur du hash: {len(hash_result)} caractères")
            print("=" * 50)
        else:
            print(f"MD5: {hash_result}")
            
    elif args.file:
        try:
            with open(args.file, 'rb') as f:
                message = f.read()
                hash_result = md5_hexdigest(message)
                
            if args.verbose:
                print("=" * 50)
                print("CALCULATEUR MD5")
                print("=" * 50)
                print(f"Fichier: {args.file}")
                print(f"Taille: {len(message)} octets")
                if len(message) > 1024*1024:
                    print(f"Taille: {len(message)/(1024*1024):.2f} MB")
                elif len(message) > 1024:
                    print(f"Taille: {len(message)/1024:.2f} KB")
                print("-" * 50)
                print(f"Empreinte MD5: {hash_result}")
                print("=" * 50)
            else:
                print(f"MD5: {hash_result}")
                
        except FileNotFoundError:
            print(f"❌ Erreur: Le fichier '{args.file}' n'existe pas.")
            sys.exit(1)
        except Exception as e:
            print(f"❌ Erreur lors de la lecture du fichier: {e}")
            sys.exit(1)
    else:
        # Aucun argument fourni, afficher l'aide
        parser.print_help()

if __name__ == "__main__":
    main()