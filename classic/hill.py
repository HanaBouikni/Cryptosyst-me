
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Chiffre de Hill
Implémentation du chiffre de Hill pour le cas bigramme (matrice 2x2)
"""

import sys
import re
import numpy as np


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


def determinant_mod(matrix, mod):
    """Calcule le déterminant d'une matrice 2x2 modulo mod."""
    return (matrix[0, 0] * matrix[1, 1] - matrix[0, 1] * matrix[1, 0]) % mod


def inverse_matrix_mod(matrix, mod):
    """
    Calcule l'inverse d'une matrice 2x2 modulo mod.
    La matrice doit être inversible modulo mod.
    """
    # Calcul du déterminant
    det = determinant_mod(matrix, mod)
    
    # Vérifier que la matrice est inversible
    if pgcd(det, mod) != 1:
        raise ValueError(f"La matrice n'est pas inversible modulo {mod}. Le déterminant ({det}) doit être premier avec {mod}.")
    
    # Calcul de l'inverse du déterminant
    det_inv = mod_inverse(det, mod)
    
    # Calcul de la matrice adjointe
    adj = np.array([
        [matrix[1, 1], (-matrix[0, 1]) % mod],
        [(-matrix[1, 0]) % mod, matrix[0, 0]]
    ])
    
    # Calcul de l'inverse: (1/det) * adj
    inv = (det_inv * adj) % mod
    
    return inv


def chiffrer_hill(texte, key_matrix):
    """
    Chiffre un texte avec le chiffre de Hill (matrice 2x2).
    La matrice clé doit être inversible modulo 26.
    """
    # Vérifier que la matrice est inversible
    det = determinant_mod(key_matrix, 26)
    if pgcd(det, 26) != 1:
        raise ValueError("La matrice clé n'est pas inversible modulo 26. Son déterminant doit être premier avec 26.")
    
    # Convertir le texte en nombres
    nums = text_to_numbers(texte)
    
    # Ajouter un padding si nécessaire pour avoir un nombre pair de caractères
    if len(nums) % 2 != 0:
        nums.append(23)  # Ajouter 'X' si le message a une longueur impaire
    
    # Chiffrer par pairs de lettres
    result = []
    for i in range(0, len(nums), 2):
        pair = np.array([nums[i], nums[i+1]])
        # Appliquer la transformation linéaire: C = K * P (mod 26)
        encrypted_pair = np.dot(key_matrix, pair) % 26
        result.extend(encrypted_pair)
    
    return numbers_to_text(result)


def dechiffrer_hill(texte_chiffre, key_matrix):
    """
    Déchiffre un texte chiffré avec le chiffre de Hill.
    Utilise l'inverse de la matrice clé.
    """
    # Calculer l'inverse de la matrice clé
    try:
        inv_key = inverse_matrix_mod(key_matrix, 26)
    except ValueError as e:
        raise ValueError(f"Impossible de déchiffrer: {e}")
    
    # Convertir le texte chiffré en nombres
    nums = text_to_numbers(texte_chiffre)
    
    # Vérifier que le texte chiffré a un nombre pair de caractères
    if len(nums) % 2 != 0:
        raise ValueError("Le texte chiffré doit avoir un nombre pair de caractères.")
    
    # Déchiffrer par pairs de lettres
    result = []
    for i in range(0, len(nums), 2):
        pair = np.array([nums[i], nums[i+1]])
        # Appliquer la transformation inverse: P = K^(-1) * C (mod 26)
        decrypted_pair = np.dot(inv_key, pair) % 26
        result.extend(decrypted_pair)
    
    return numbers_to_text(result)


def parse_matrix(input_str):
    """
    Parse une chaîne d'entrée pour en faire une matrice 2x2.
    Format attendu: "a b c d" où a, b, c, d sont les éléments de la matrice.
    """
    try:
        elements = list(map(int, input_str.split()))
        if len(elements) != 4:
            raise ValueError("La matrice doit contenir exactement 4 éléments")
        return np.array([[elements[0], elements[1]], [elements[2], elements[3]]])
    except Exception as e:
        raise ValueError(f"Format de matrice invalide: {e}")


def main():
    """Fonction principale pour l'interface en ligne de commande."""
    print("=" * 80)
    print("SYSTÈME DE CHIFFREMENT HILL (MATRICE 2x2)")
    print("=" * 80)
    
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
                
            matrice_str = input("Entrez la matrice clé (4 entiers séparés par des espaces, ex: '9 4 5 7'): ")
            if not matrice_str:
                print("Matrice vide, opération annulée.")
                continue
            
            try:
                key_matrix = parse_matrix(matrice_str)
                texte_chiffre = chiffrer_hill(texte, key_matrix)
                
                print(f"\nMatrice clé:\n{key_matrix}")
                print(f"Texte clair   : {re.sub(r'[^A-Za-z]', '', texte.upper())}")
                print(f"Texte chiffré : {texte_chiffre}")
                
            except ValueError as e:
                print(f"\n❌ Erreur: {e}")
        
        elif choice == "2":
            # Déchiffrement
            texte_chiffre = input("\nEntrez le texte chiffré: ")
            if not texte_chiffre:
                print("Message vide, opération annulée.")
                continue
                
            matrice_str = input("Entrez la matrice clé utilisée pour le chiffrement (4 entiers séparés par des espaces, ex: '9 4 5 7'): ")
            if not matrice_str:
                print("Matrice vide, opération annulée.")
                continue
            
            try:
                key_matrix = parse_matrix(matrice_str)
                texte_clair = dechiffrer_hill(texte_chiffre, key_matrix)
                
                print(f"\nMatrice clé:\n{key_matrix}")
                print(f"Matrice inverse modulo 26:\n{inverse_matrix_mod(key_matrix, 26)}")
                print(f"Texte chiffré  : {re.sub(r'[^A-Za-z]', '', texte_chiffre.upper())}")
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