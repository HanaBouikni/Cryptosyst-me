#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Masque Jetable (One Time Pad) Implementation

Ce script implémente le chiffrement par masque jetable (One Time Pad), un système
de chiffrement inconditionellement sûr où chaque caractère du message est combiné
avec un caractère de la clé qui doit être complètement aléatoire et utilisée une seule fois.
"""

import random
import string

def generate_random_key(length):
    """
    Génère une clé aléatoire de la longueur spécifiée.
    
    Args:
        length (int): Longueur de la clé à générer
    
    Returns:
        str: Clé aléatoire générée
    """
    return ''.join(random.choice(string.ascii_uppercase) for _ in range(length))

def otp_encrypt(plaintext, key):
    """
    Chiffre un message en utilisant le masque jetable (OTP).
    
    Args:
        plaintext (str): Message en clair à chiffrer
        key (str): Clé de chiffrement (doit être de même longueur que plaintext)
    
    Returns:
        str: Message chiffré
    """
    # Convertir en majuscules et supprimer les caractères non alphabétiques
    plaintext = ''.join(c.upper() for c in plaintext if c.isalpha())
    
    if len(key) < len(plaintext):
        raise ValueError("La clé doit être au moins aussi longue que le message")
    
    ciphertext = ''
    for i in range(len(plaintext)):
        # Calculer le caractère chiffré en utilisant XOR (simulé avec des décalages)
        p_val = ord(plaintext[i]) - ord('A')
        k_val = ord(key[i]) - ord('A')
        c_val = (p_val + k_val) % 26
        ciphertext += chr(c_val + ord('A'))
    
    return ciphertext

def otp_decrypt(ciphertext, key):
    """
    Déchiffre un message chiffré avec masque jetable (OTP).
    
    Args:
        ciphertext (str): Message chiffré à déchiffrer
        key (str): Clé de chiffrement (doit être de même longueur que ciphertext)
    
    Returns:
        str: Message déchiffré
    """
    if len(key) < len(ciphertext):
        raise ValueError("La clé doit être au moins aussi longue que le message chiffré")
    
    plaintext = ''
    for i in range(len(ciphertext)):
        # Calculer le caractère déchiffré en utilisant XOR inverse (simulé avec des décalages)
        c_val = ord(ciphertext[i]) - ord('A')
        k_val = ord(key[i]) - ord('A')
        p_val = (c_val - k_val) % 26
        plaintext += chr(p_val + ord('A'))
    
    return plaintext

def display_example(plaintext, key):
    """
    Affiche un exemple de chiffrement OTP avec les détails.
    
    Args:
        plaintext (str): Message en clair
        key (str): Clé utilisée
    """
    # Formatage pour l'affichage
    plaintext = ''.join(c.upper() for c in plaintext if c.isalpha())
    ciphertext = otp_encrypt(plaintext, key)
    
    print("\n" + "=" * 80)
    print("EXEMPLE DE CHIFFREMENT PAR MASQUE JETABLE (OTP)")
    print("=" * 80)
    
    print(f"\nClair   : {plaintext}")
    print(f"Clé     : {key[:len(plaintext)]}")
    print(f"Chiffré : {ciphertext}")
    
    print("\nExplication du processus de chiffrement:")
    print("-" * 50)
    print("Lettre du message + Lettre de la clé = Lettre chiffrée (mod 26)")
    
    for i in range(min(10, len(plaintext))):  # Montrer les 10 premiers caractères
        p_val = ord(plaintext[i]) - ord('A')
        k_val = ord(key[i]) - ord('A')
        c_val = (p_val + k_val) % 26
        print(f"{plaintext[i]} ({p_val:2d}) + {key[i]} ({k_val:2d}) = {ciphertext[i]} ({c_val:2d})")
    
    if len(plaintext) > 10:
        print("...")
    
    print("=" * 80)

def print_otp_info():
    """
    Affiche des informations sur le masque jetable (OTP).
    """
    print("\n" + "=" * 80)
    print("INFORMATION SUR LE MASQUE JETABLE (ONE TIME PAD)")
    print("=" * 80)
    print("""
Le masque jetable (OTP) est un algorithme inconditionnellement sûr

Le masque jetable est le seul algorithme de cryptage connu comme étant
indécryptable. C'est un chiffre de Vigenère avec comme caractéristique :
la clé de chiffrement a la même longueur que le message clair.

Conditions d'utilisation de la clé :
• La clé doit être aussi longue que le texte clair.
• Utiliser une clé formée d'une suite de caractères aléatoires.
• Ne jamais réutiliser une clé, chaque clé est utilisée une seule fois.
""")
    print("=" * 80)

def main():
    """
    Fonction principale qui gère le flux d'exécution du programme.
    """
    print("=" * 80)
    print("SYSTÈME DE CHIFFREMENT PAR MASQUE JETABLE (ONE TIME PAD)")
    print("=" * 80)
    
    # Menu principal
    while True:
        print("\n1. Chiffrer un message")
        print("2. Déchiffrer un message")
        print("3. Générer une clé aléatoire")
        print("4. Afficher un exemple")
        print("5. Informations sur le masque jetable")
        print("6. Quitter")
        
        choice = input("\nVotre choix (1-6): ").strip()
        
        if choice == "1":
            # Chiffrement
            plaintext = input("\nEntrez le message à chiffrer: ")
            if not plaintext:
                print("Message vide, opération annulée.")
                continue
            
            # Nettoyage du texte
            clean_text = ''.join(c.upper() for c in plaintext if c.isalpha())
            if not clean_text:
                print("Le message ne contient aucun caractère alphabétique valide.")
                continue
                
            print(f"Message préparé: {clean_text}")
            
            key_choice = input("Voulez-vous générer une clé aléatoire? (O/n): ").strip().lower()
            if key_choice != 'n':
                key = generate_random_key(len(clean_text))
                print(f"Clé générée: {key}")
            else:
                key = input("Entrez votre clé (lettres uniquement): ").upper()
                key = ''.join(c for c in key if c.isalpha())
                
                if len(key) < len(clean_text):
                    print(f"Attention: La clé est trop courte ({len(key)} < {len(clean_text)})")
                    print("La clé sera complétée avec des caractères aléatoires.")
                    key += generate_random_key(len(clean_text) - len(key))
                    print(f"Nouvelle clé: {key}")
            
            try:
                ciphertext = otp_encrypt(clean_text, key)
                print(f"\nMessage chiffré: {ciphertext}")
            except Exception as e:
                print(f"\n❌ Erreur lors du chiffrement: {e}")
            
        elif choice == "2":
            # Déchiffrement
            ciphertext = input("\nEntrez le message à déchiffrer: ").upper()
            if not ciphertext:
                print("Message vide, opération annulée.")
                continue
            
            # Nettoyage du texte chiffré
            ciphertext = ''.join(c for c in ciphertext if c.isalpha())
            if not ciphertext:
                print("Le message ne contient aucun caractère alphabétique valide.")
                continue
            
            key = input("Entrez la clé de déchiffrement: ").upper()
            key = ''.join(c for c in key if c.isalpha())
            
            if len(key) < len(ciphertext):
                print(f"Attention: La clé est trop courte ({len(key)} < {len(ciphertext)})")
                continue
            
            try:
                plaintext = otp_decrypt(ciphertext, key)
                print(f"\nMessage déchiffré: {plaintext}")
            except Exception as e:
                print(f"\n❌ Erreur lors du déchiffrement: {e}")
            
        elif choice == "3":
            # Génération de clé
            try:
                length = int(input("\nEntrez la longueur de la clé: "))
                if length <= 0:
                    print("La longueur doit être un nombre positif.")
                    continue
                
                key = generate_random_key(length)
                print(f"\nClé générée ({length} caractères): {key}")
            except ValueError:
                print("Veuillez entrer un nombre entier valide.")
            
        elif choice == "4":
            # Afficher un exemple
            example_text = "MASQUEJETABLE"
            example_key = generate_random_key(len(example_text))
            display_example(example_text, example_key)
            
        elif choice == "5":
            # Informations sur OTP
            print_otp_info()
            
        elif choice == "6":
            # Quitter
            print("\nAu revoir!")
            break
            
        else:
            print("\nOption invalide. Veuillez choisir entre 1 et 6.")
    
    print("\n" + "=" * 80)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nOpération interrompue par l'utilisateur.")
    except Exception as e:
        print(f"\n❌ Erreur: {e}")