#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Substitution Cipher Implementation

Ce script implémente le chiffrement par substitution, une méthode qui remplace chaque 
lettre par une autre lettre ou symbole selon une correspondance définie par une clé.
"""

import random

def substitution_cipher(text, key, action="encrypt"):
    """
    Implémente l'algorithme du chiffrement par substitution.
    
    Args:
        text (str): Texte à chiffrer ou déchiffrer
        key (str): Clé de substitution (26 lettres uniques)
        action (str): 'encrypt' pour chiffrer, 'decrypt' pour déchiffrer
    
    Returns:
        str: Le texte chiffré ou déchiffré
    """
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    key = key.upper()
    
    # Vérifier que la clé contient 26 lettres uniques
    if len(key) != 26 or len(set(key)) != 26 or not all(c.isalpha() for c in key):
        raise ValueError("La clé doit contenir exactement 26 lettres uniques")
    
    # Construire le mapping pour le chiffrement ou le déchiffrement
    mapping = {}
    for i in range(26):
        plain_char = alphabet[i]
        cipher_char = key[i]
        
        if action == "encrypt":
            mapping[plain_char] = cipher_char
            mapping[plain_char.lower()] = cipher_char.lower()
        else:  # decrypt
            mapping[cipher_char] = plain_char
            mapping[cipher_char.lower()] = plain_char.lower()
    
    # Appliquer le mapping au texte
    result = "".join(mapping.get(char, char) for char in text)
    
    return result

def generate_random_key():
    """
    Génère une clé aléatoire de 26 lettres.
    
    Returns:
        str: Une clé de substitution aléatoire
    """
    alphabet = list("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
    random.shuffle(alphabet)
    return "".join(alphabet)

def main():
    """
    Fonction principale qui gère le flux d'exécution du programme.
    """
    print("=" * 80)
    print("SYSTÈME DE CHIFFREMENT PAR SUBSTITUTION")
    print("=" * 80)
    
    # Menu principal
    while True:
        print("\n1. Chiffrer un message")
        print("2. Déchiffrer un message")
        print("3. Générer une clé aléatoire")
        print("4. Quitter")
        
        choice = input("\nVotre choix (1-4): ").strip()
        
        if choice == "1":
            # Chiffrement
            plaintext = input("\nEntrez le message à chiffrer: ")
            if not plaintext:
                print("Message vide, opération annulée.")
                continue
            
            key = input("Entrez la clé de substitution (26 lettres): ")
            
            try:
                ciphertext = substitution_cipher(plaintext, key, "encrypt")
                print(f"\nMessage chiffré: {ciphertext}")
            except ValueError as e:
                print(f"\n❌ Erreur: {e}")
            
        elif choice == "2":
            # Déchiffrement
            ciphertext = input("\nEntrez le message à déchiffrer: ")
            if not ciphertext:
                print("Message vide, opération annulée.")
                continue
            
            key = input("Entrez la clé de substitution (26 lettres): ")
            
            try:
                plaintext = substitution_cipher(ciphertext, key, "decrypt")
                print(f"\nMessage déchiffré: {plaintext}")
            except ValueError as e:
                print(f"\n❌ Erreur: {e}")
            
        elif choice == "3":
            # Génération de clé
            random_key = generate_random_key()
            print(f"\nClé de substitution aléatoire générée: {random_key}")
            
        elif choice == "4":
            # Quitter
            print("\nAu revoir!")
            break
            
        else:
            print("\nOption invalide. Veuillez choisir entre 1 et 4.")
    
    print("\n" + "=" * 80)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nOpération interrompue par l'utilisateur.")
    except Exception as e:
        print(f"\n❌ Erreur: {e}")