#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Chiffrement affine
Implémentation du chiffre affine: y = (ax + b) mod 26
"""

import sys
import re
import math


def pgcd(a, b):
    """Calcule le PGCD de deux nombres."""
    while b:
        a, b = b, a % b
    return a


def mod_inverse(a, m):
    """
    Calcule l'inverse modulaire de a modulo m.
    Utilise l'algorithme d'Euclide étendu.
    """
    if pgcd(a, m) != 1:
        raise ValueError(f"L'inverse modulaire n'existe pas car {a} et {m} ne sont pas premiers entre eux")
    
    # Algorithme d'Euclide étendu
    u1, u2, u3 = 1, 0, a
    v1, v2, v3 = 0, 1, m
    
    while v3 != 0:
        q = u3 // v3
        v1, v2, v3, u1, u2, u3 = (u1 - q * v1), (u2 - q * v2), (u3 - q * v3), v1, v2, v3
    
    # Assurer que le résultat est positif
    return u1 % m


def text_to_numbers(text):
    """Convertit un texte en une liste de nombres (A=0, B=1, ..., Z=25)."""
    # Convertir en majuscules et supprimer les caractères non alphabétiques
    text = re.sub(r'[^A-Za-z]', '', text.upper())
    # Convertir chaque lettre en nombre
    return [ord(char) - ord('A') for char in text]


def numbers_to_text(numbers):
    """Convertit une liste de nombres en texte."""
    return ''.join([chr(n + ord('A')) for n in numbers])


def chiffrer_affine(texte, a, b):
    """
    Chiffre un texte avec le chiffre affine: y = (ax + b) mod 26
    a et b doivent être des entiers, et a doit être premier avec 26
    """
    # Vérifier que a est premier avec 26 (taille de l'alphabet)
    if pgcd(a, 26) != 1:
        raise ValueError("La valeur de 'a' doit être première avec 26")
    
    # Convertir le texte en nombres
    nombres = text_to_numbers(texte)
    
    # Appliquer la fonction de chiffrement: y = (ax + b) mod 26
    chiffres = [(a * x + b) % 26 for x in nombres]
    
    # Convertir les nombres en texte
    return numbers_to_text(chiffres)


def dechiffrer_affine(texte_chiffre, a, b):
    """
    Déchiffre un texte chiffré avec le chiffre affine
    Utilise la formule: x = a^(-1) * (y - b) mod 26
    """
    # Calculer l'inverse modulaire de a
    a_inv = mod_inverse(a, 26)
    
    # Convertir le texte chiffré en nombres
    nombres_chiffres = text_to_numbers(texte_chiffre)
    
    # Appliquer la fonction de déchiffrement: x = a^(-1) * (y - b) mod 26
    nombres_clairs = [(a_inv * (y - b)) % 26 for y in nombres_chiffres]
    
    # Convertir les nombres en texte
    return numbers_to_text(nombres_clairs)


def afficher_valeurs_a_valides():
    """Affiche les valeurs valides pour a (celles qui sont premières avec 26)."""
    valides = [a for a in range(1, 26) if pgcd(a, 26) == 1]
    print(f"Valeurs valides pour 'a' (premières avec 26): {valides}")


def main():
    """Fonction principale pour l'interface en ligne de commande."""
    print("=" * 80)
    print("SYSTÈME DE CHIFFREMENT AFFINE")
    print("=" * 80)
    print("y = (ax + b) mod 26")
    
    # Afficher les valeurs valides pour a
    afficher_valeurs_a_valides()
    
    # Menu principal
    while True:
        print("\n1. Chiffrer un message")
        print("2. Déchiffrer un message")
        print("3. Quitter")
        
        choice = input("\nVotre choix (1-3): ").strip()
        
        if choice == "1":
            # Chiffrement
            texte = input("\nEntrez le texte à chiffrer: ")
            if not texte:
                print("Message vide, opération annulée.")
                continue
                
            try:
                a_input = input("Entrez la valeur de 'a' (doit être premier avec 26): ")
                a = int(a_input) if a_input.strip() else 1
                
                b_input = input("Entrez la valeur de 'b' (entre 0 et 25): ")
                b = int(b_input) if b_input.strip() else 0
                
                # Vérifier les valeurs
                if pgcd(a, 26) != 1:
                    print("\n❌ Erreur: 'a' doit être premier avec 26.")
                    continue
                
                if not (0 <= b <= 25):
                    print("\n❌ Erreur: 'b' doit être entre 0 et 25.")
                    continue
                
                texte_chiffre = chiffrer_affine(texte, a, b)
                print(f"\nTexte clair   : {re.sub(r'[^A-Za-z]', '', texte.upper())}")
                print(f"Texte chiffré : {texte_chiffre}")
                
            except ValueError as e:
                print(f"\n❌ Erreur: {e}")
        
        elif choice == "2":
            # Déchiffrement
            texte_chiffre = input("\nEntrez le texte chiffré: ")
            if not texte_chiffre:
                print("Message vide, opération annulée.")
                continue
                
            try:
                a_input = input("Entrez la valeur de 'a' utilisée pour le chiffrement: ")
                a = int(a_input) if a_input.strip() else 1
                
                b_input = input("Entrez la valeur de 'b' utilisée pour le chiffrement: ")
                b = int(b_input) if b_input.strip() else 0
                
                # Vérifier les valeurs
                if pgcd(a, 26) != 1:
                    print("\n❌ Erreur: 'a' doit être premier avec 26.")
                    continue
                
                if not (0 <= b <= 25):
                    print("\n❌ Erreur: 'b' doit être entre 0 et 25.")
                    continue
                
                texte_clair = dechiffrer_affine(texte_chiffre, a, b)
                print(f"\nTexte chiffré : {re.sub(r'[^A-Za-z]', '', texte_chiffre.upper())}")
                print(f"Texte déchiffré: {texte_clair}")
                
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