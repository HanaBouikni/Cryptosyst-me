#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Vigenère Cipher Implementation

Ce script implémente le chiffrement Vigenère, une méthode de chiffrement par substitution 
polyalphabétique utilisant une série de chiffrements de César différents basés sur les 
lettres d'un mot-clé.
"""

def vigenere_cipher(text, key, action="encrypt"):
    """
    Implémente l'algorithme du chiffrement Vigenère.
    
    Args:
        text (str): Texte à chiffrer ou déchiffrer
        key (str): Clé de chiffrement ou déchiffrement
        action (str): 'encrypt' pour chiffrer, 'decrypt' pour déchiffrer
    
    Returns:
        str: Le texte chiffré ou déchiffré
    """
    # Nettoyer et normaliser la clé (seulement des lettres majuscules)
    key = ''.join(filter(str.isalpha, key.upper()))
    
    if not key:
        raise ValueError("Clé invalide, veuillez n'utiliser que des lettres")
    
    key_length = len(key)
    key_as_int = [ord(k) - ord('A') for k in key]
    result = ""
    key_index = 0
    
    for char in text:
        if char.isalpha():
            # Déterminer si majuscule ou minuscule
            is_upper = char.isupper()
            char = char.upper()
            
            # Obtenir le décalage à partir du caractère actuel de la clé
            key_char = key_as_int[key_index % key_length]
            
            # Ajuster la direction du décalage en fonction de l'action
            if action == "decrypt":
                key_char = -key_char
            
            # Appliquer le décalage avec le bon enroulement
            shifted = (ord(char) - ord('A') + key_char) % 26
            if is_upper:
                result += chr(shifted + ord('A'))
            else:
                result += chr(shifted + ord('A')).lower()
            
            key_index += 1
        else:
            # Conserver les caractères non alphabétiques
            result += char
    
    return result

def main():
    """
    Fonction principale qui gère le flux d'exécution du programme.
    """
    print("=" * 80)
    print("SYSTÈME DE CHIFFREMENT VIGENÈRE")
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
            
            key = input("Entrez la clé de chiffrement: ")
            if not key or not any(c.isalpha() for c in key):
                print("Clé invalide, veuillez entrer au moins une lettre.")
                continue
            
            try:
                ciphertext = vigenere_cipher(plaintext, key, "encrypt")
                print(f"\nMessage chiffré: {ciphertext}")
            except ValueError as e:
                print(f"\n❌ Erreur: {e}")
            
        elif choice == "2":
            # Déchiffrement
            ciphertext = input("\nEntrez le message à déchiffrer: ")
            if not ciphertext:
                print("Message vide, opération annulée.")
                continue
            
            key = input("Entrez la clé de déchiffrement: ")
            if not key or not any(c.isalpha() for c in key):
                print("Clé invalide, veuillez entrer au moins une lettre.")
                continue
            
            try:
                plaintext = vigenere_cipher(ciphertext, key, "decrypt")
                print(f"\nMessage déchiffré: {plaintext}")
            except ValueError as e:
                print(f"\n❌ Erreur: {e}")
            
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