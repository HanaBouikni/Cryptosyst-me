#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
César Cipher Implementation

Ce script implémente le chiffrement César, une technique de chiffrement par substitution
où chaque lettre est remplacée par une lettre décalée d'un certain nombre de positions
dans l'alphabet.
"""

def cesar_cipher(text, shift, action="encrypt"):
    """
    Implémente l'algorithme de chiffrement César.
    
    Args:
        text (str): Texte à chiffrer ou déchiffrer
        shift (int): Nombre de positions à décaler chaque caractère
        action (str): 'encrypt' pour chiffrer, 'decrypt' pour déchiffrer
    
    Returns:
        str: Le texte chiffré ou déchiffré
    """
    # Ajuster le décalage en fonction de l'action
    if action == "decrypt":
        shift = -shift
    
    # S'assurer que le décalage est dans la plage de l'alphabet (modulo 26)
    shift = ((shift % 26) + 26) % 26
    
    result = ""
    for char in text:
        if char.isalpha():
            # Déterminer si majuscule ou minuscule
            ascii_offset = ord('A') if char.isupper() else ord('a')
            
            # Appliquer le décalage avec le bon enroulement
            shifted_char = chr(((ord(char) - ascii_offset + shift) % 26) + ascii_offset)
            result += shifted_char
        else:
            # Conserver les caractères non alphabétiques
            result += char
    
    return result

def main():
    """
    Fonction principale qui gère le flux d'exécution du programme.
    """
    print("=" * 80)
    print("SYSTÈME DE CHIFFREMENT CÉSAR")
    print("=" * 80)
    
    # Menu principal
    while True:
        print("\n1. Chiffrer un message")
        print("2. Déchiffrer un message")
        print("3. Quitter")
        
        choice = input("\nVotre choix (1-3): ").strip()
        
        if choice == "1":
            # Chiffrement
            plaintext = input("\nEntrez le message à chiffrer: ")
            if not plaintext:
                print("Message vide, opération annulée.")
                continue
            
            shift_input = input("Entrez le décalage (nombre entier, défaut: 3): ")
            shift = int(shift_input) if shift_input.strip() else 3
            
            ciphertext = cesar_cipher(plaintext, shift, "encrypt")
            print(f"\nMessage chiffré: {ciphertext}")
            
        elif choice == "2":
            # Déchiffrement
            ciphertext = input("\nEntrez le message à déchiffrer: ")
            if not ciphertext:
                print("Message vide, opération annulée.")
                continue
            
            shift_input = input("Entrez le décalage (nombre entier, défaut: 3): ")
            shift = int(shift_input) if shift_input.strip() else 3
            
            plaintext = cesar_cipher(ciphertext, shift, "decrypt")
            print(f"\nMessage déchiffré: {plaintext}")
            
        elif choice == "3":
            # Quitter
            print("\nAu revoir!")
            break
            
        else:
            print("\nOption invalide. Veuillez choisir entre 1 et 3.")
    
    print("\n" + "=" * 80)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nOpération interrompue par l'utilisateur.")
    except Exception as e:
        print(f"\n❌ Erreur: {e}")