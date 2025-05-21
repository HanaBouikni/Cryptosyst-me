#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import re


def index_of_coincidence(text):
    """
    Calcule l'Index of Coincidence (IOC).
    IOC = (1 / (N*(N-1))) * SUM( freq[i] * (freq[i] - 1) )
    """
    # Nettoyer le texte et convertir en majuscules
    cleaned = re.sub(r'[^A-Z]', '', text.upper())
    length = len(cleaned)
    
    if length < 2:
        return 0
    
    # Compter les occurrences de chaque lettre
    counts = {}
    for c in cleaned:
        counts[c] = counts.get(c, 0) + 1
    
    # Calculer le numérateur de l'IOC
    numerator = 0
    for c in counts:
        numerator += counts[c] * (counts[c] - 1)
    
    # Calculer et retourner l'IOC
    return numerator / (length * (length - 1))


def interpret_ioc(ioc):
    """
    Interprétation de l'IOC
    """
    interpretation = f"Interprétation:\n"
    
    if ioc >= 0.065:
        interpretation += f"IOC élevé (≥0.065) - Texte probablement en clair (français)\n"
        interpretation += f"ou chiffrement monoalphabétique (César, substitution)."
    elif ioc >= 0.045:
        interpretation += f"IOC modéré (0.045-0.065) - Chiffrement polyalphabétique\n"
        interpretation += f"probable (Vigenère) avec clé courte."
    elif ioc >= 0.035:
        interpretation += f"IOC faible (0.035-0.045) - Chiffrement polyalphabétique\n"
        interpretation += f"avec clé de longueur moyenne, ou chiffrement complexe."
    else:
        interpretation += f"IOC très faible (<0.035) - Chiffrement fort, clé très longue,\n"
        interpretation += f"ou données quasi-aléatoires."

    interpretation += f"\n\nRéférences:\n"
    interpretation += f"- Français: ~0.078\n"
    interpretation += f"- Anglais: ~0.067\n"
    interpretation += f"- Aléatoire: ~0.038"

    return interpretation


def main():
    parser = argparse.ArgumentParser(description='Calcul de l\'Index de Coïncidence d\'un texte.')
    parser.add_argument('-f', '--file', help='Fichier texte à analyser')
    parser.add_argument('-t', '--text', help='Texte à analyser directement')
    
    args = parser.parse_args()
    
    # Obtenir le texte soit du fichier, soit de l'argument, soit de l'entrée standard
    if args.file:
        try:
            with open(args.file, 'r', encoding='utf-8') as f:
                text = f.read()
        except Exception as e:
            print(f"Erreur lors de la lecture du fichier: {e}")
            return
    elif args.text:
        text = args.text
    else:
        print("Veuillez entrer le texte à analyser (appuyez sur Ctrl+D pour terminer):")
        try:
            text = ''.join(iter(input, ''))
        except EOFError:
            text = ''
    
    if not text.strip():
        print("Erreur: Aucun texte fourni pour l'analyse.")
        return
    
    # Calculer l'IOC et afficher l'interprétation
    ioc = index_of_coincidence(text)
    interpretation = interpret_ioc(ioc)
    
    print(f"Index of Coincidence: {ioc:.4f}\n")
    print(interpretation)


if __name__ == "__main__":
    main()