#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import re
import sys


def get_letter_frequencies(text):
    """
    Calcule la fréquence des lettres a-z (insensible à la casse).
    """
    # Nettoyer le texte et convertir en majuscules
    letters = re.sub(r'[^A-Z]', '', text.upper())
    
    # Compter toutes les lettres présentes
    freq = {}
    for c in letters:
        freq[c] = freq.get(c, 0) + 1
    
    # Convertir en pourcentages
    total = len(letters) or 1  # Éviter division par zéro
    for c in freq:
        freq[c] = f"{(freq[c] / total * 100):.2f}%"
    
    return freq


def display_frequency_results(frequencies, original_text):
    """
    Affichage amélioré des résultats de fréquence
    """
    cleaned_text = re.sub(r'[^A-Z]', '', original_text.upper())
    result = "ANALYSE DE FRÉQUENCE\n"
    result += "====================\n\n"
    result += f"Texte analysé: {len(cleaned_text)} lettres\n"
    result += f"Texte original: {len(original_text)} caractères\n\n"

    # Convertir les pourcentages en nombres pour le tri
    freq_entries = []
    for letter, percent in frequencies.items():
        freq_entries.append([letter, float(percent.replace('%', ''))])

    # Trier par fréquence décroissante
    freq_entries.sort(key=lambda x: x[1], reverse=True)

    result += "Fréquences (triées par ordre décroissant):\n"
    result += "------------------------------------------\n"
    
    for letter, freq in freq_entries:
        bar = '█' * max(1, round(freq / 2))
        result += f"{letter}: {freq:.2f}% {bar}\n"

    result += "\n\nFréquences théoriques du français:\n"
    result += "E: 14.7%  A: 7.6%   I: 7.5%   S: 7.9%   N: 7.1%\n"
    result += "R: 6.6%   T: 7.2%   O: 5.3%   L: 5.5%   U: 6.3%\n"

    return result


def main():
    parser = argparse.ArgumentParser(description='Analyse de fréquence des lettres dans un texte.')
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
        # Lecture directe depuis stdin, adapté pour Windows/PowerShell
        print("Veuillez entrer le texte à analyser (terminez avec Entrée puis Ctrl+Z sur Windows ou Ctrl+D sur Unix):")
        try:
            text = sys.stdin.read()
        except KeyboardInterrupt:
            print("\nOpération annulée.")
            return
    
    if not text.strip():
        print("Erreur: Aucun texte fourni pour l'analyse.")
        return
    
    # Calculer et afficher les fréquences
    frequencies = get_letter_frequencies(text)
    result = display_frequency_results(frequencies, text)
    print(result)


if __name__ == "__main__":
    main()