#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Chiffre de Playfair
Implémentation du chiffre de Playfair utilisant une grille 5x5
"""

import re


def preparer_cle(cle):
    """
    Prépare la clé pour le chiffre de Playfair en éliminant les doublons
    et en créant une version utilisable pour la grille 5x5.
    """
    # Convertir en majuscules et garder uniquement les lettres
    cle = re.sub(r'[^A-Za-z]', '', cle.upper())
    
    # Remplacer J par I car la grille est 5x5 (25 lettres)
    cle = cle.replace('J', 'I')
    
    # Éliminer les doublons tout en préservant l'ordre
    cle_sans_doublons = ""
    for char in cle:
        if char not in cle_sans_doublons:
            cle_sans_doublons += char
    
    return cle_sans_doublons


def creer_grille_playfair(cle):
    """
    Crée la grille 5x5 pour le chiffre de Playfair.
    La clé est placée au début, puis le reste de l'alphabet est ajouté.
    """
    # Préparer la clé
    cle_preparee = preparer_cle(cle)
    
    # Ajouter le reste de l'alphabet
    alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"  # Sans le J
    for char in cle_preparee:
        alphabet = alphabet.replace(char, '')
    
    # Combiner la clé et le reste de l'alphabet
    contenu_grille = cle_preparee + alphabet
    
    # Créer la grille 5x5
    grille = [[contenu_grille[i*5 + j] for j in range(5)] for i in range(5)]
    
    return grille


def afficher_grille(grille):
    """Affiche la grille de Playfair de manière lisible."""
    print("\nGrille de Playfair:")
    print("  | " + " | ".join(str(i) for i in range(5)) + " |")
    print("-" * 21)
    for i, ligne in enumerate(grille):
        print(f"{i} | " + " | ".join(ligne) + " |")
    print("")


def trouver_position(grille, lettre):
    """
    Trouve la position (ligne, colonne) d'une lettre dans la grille.
    Si la lettre est J, on cherche I (convention du chiffre de Playfair).
    """
    if lettre == 'J':
        lettre = 'I'
    
    for i in range(5):
        for j in range(5):
            if grille[i][j] == lettre:
                return i, j
    
    return -1, -1  # Ne devrait jamais arriver si la grille est correcte


def preparer_message(message):
    """
    Prépare le message pour le chiffrement de Playfair:
    - Convertit en majuscules
    - Supprime les caractères non alphabétiques
    - Remplace J par I
    - Divise le message en bigrammes
    - Évite les bigrammes de lettres identiques en insérant X
    - Ajoute X à la fin si nécessaire pour avoir un nombre pair de lettres
    """
    # Convertir en majuscules et supprimer les caractères non alphabétiques
    message = re.sub(r'[^A-Za-z]', '', message.upper())
    
    # Remplacer J par I
    message = message.replace('J', 'I')
    
    # Préparer les bigrammes
    bigrammes = []
    i = 0
    while i < len(message):
        # Si on est au dernier caractère ou si deux caractères consécutifs sont identiques
        if i == len(message) - 1 or message[i] == message[i+1]:
            bigrammes.append(message[i] + 'X')
            i += 1
        else:
            bigrammes.append(message[i] + message[i+1])
            i += 2
    
    return bigrammes


def chiffrer_playfair(message, cle):
    """
    Chiffre un message avec le chiffre de Playfair.
    """
    # Créer la grille
    grille = creer_grille_playfair(cle)
    
    # Préparer le message
    bigrammes = preparer_message(message)
    
    # Chiffrer chaque bigramme
    resultat = []
    for bg in bigrammes:
        lettre1, lettre2 = bg[0], bg[1]
        row1, col1 = trouver_position(grille, lettre1)
        row2, col2 = trouver_position(grille, lettre2)
        
        # Règle 1: Si les lettres sont sur la même ligne
        if row1 == row2:
            resultat.append(grille[row1][(col1 + 1) % 5] + grille[row2][(col2 + 1) % 5])
        
        # Règle 2: Si les lettres sont dans la même colonne
        elif col1 == col2:
            resultat.append(grille[(row1 + 1) % 5][col1] + grille[(row2 + 1) % 5][col2])
        
        # Règle 3: Si les lettres forment un rectangle
        else:
            resultat.append(grille[row1][col2] + grille[row2][col1])
    
    return ''.join(resultat)


def dechiffrer_playfair(message_chiffre, cle):
    """
    Déchiffre un message chiffré avec le chiffre de Playfair.
    """
    # Créer la grille
    grille = creer_grille_playfair(cle)
    
    # Nettoyer le message chiffré
    message_chiffre = re.sub(r'[^A-Za-z]', '', message_chiffre.upper())
    
    # Diviser en bigrammes
    bigrammes = [message_chiffre[i:i+2] for i in range(0, len(message_chiffre), 2)]
    
    # Déchiffrer chaque bigramme
    resultat = []
    for bg in bigrammes:
        if len(bg) != 2:  # Ignorer les bigrammes incomplets
            continue
        
        lettre1, lettre2 = bg[0], bg[1]
        row1, col1 = trouver_position(grille, lettre1)
        row2, col2 = trouver_position(grille, lettre2)
        
        # Règle 1: Si les lettres sont sur la même ligne
        if row1 == row2:
            resultat.append(grille[row1][(col1 - 1) % 5] + grille[row2][(col2 - 1) % 5])
        
        # Règle 2: Si les lettres sont dans la même colonne
        elif col1 == col2:
            resultat.append(grille[(row1 - 1) % 5][col1] + grille[(row2 - 1) % 5][col2])
        
        # Règle 3: Si les lettres forment un rectangle
        else:
            resultat.append(grille[row1][col2] + grille[row2][col1])
    
    return ''.join(resultat)


def main():
    """
    Fonction principale qui gère le flux d'exécution du programme.
    """
    print("=" * 80)
    print("SYSTÈME DE CHIFFREMENT PLAYFAIR")
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
            
            cle = input("Entrez la clé de chiffrement: ")
            if not cle:
                print("Clé vide, opération annulée.")
                continue
            
            # Afficher la grille pour information
            grille = creer_grille_playfair(cle)
            afficher_grille(grille)
            
            bigrammes = preparer_message(plaintext)
            print(f"Bigrammes préparés: {' '.join(bigrammes)}")
            
            ciphertext = chiffrer_playfair(plaintext, cle)
            
            # Formatage par paires pour la lisibilité
            ciphertext_formate = ' '.join([ciphertext[i:i+2] for i in range(0, len(ciphertext), 2)])
            print(f"\nMessage chiffré: {ciphertext}")
            print(f"Message chiffré (formaté): {ciphertext_formate}")
            
        elif choice == "2":
            # Déchiffrement
            ciphertext = input("\nEntrez le message à déchiffrer: ")
            if not ciphertext:
                print("Message vide, opération annulée.")
                continue
            
            cle = input("Entrez la clé de déchiffrement: ")
            if not cle:
                print("Clé vide, opération annulée.")
                continue
            
            # Afficher la grille pour information
            grille = creer_grille_playfair(cle)
            afficher_grille(grille)
            
            plaintext = dechiffrer_playfair(ciphertext, cle)
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