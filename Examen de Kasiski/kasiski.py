#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import re
import math


def calculate_gcd(numbers):
    """
    Calcule le PGCD de plusieurs nombres
    """
    if not numbers:
        return 0
    if len(numbers) == 1:
        return numbers[0]
    
    def gcd(a, b):
        while b:
            a, b = b, a % b
        return a
    
    result = numbers[0]
    for i in range(1, len(numbers)):
        result = gcd(result, numbers[i])
        if result == 1:  # Optimisation: si PGCD = 1, pas besoin de continuer
            break
    
    return result


def analyze_factors(distances):
    """
    Analyse des facteurs pour Kasiski
    """
    factor_count = {}
    
    for distance in distances:
        # Trouver tous les facteurs de cette distance
        for factor in range(2, distance + 1):
            if distance % factor == 0:
                factor_count[factor] = factor_count.get(factor, 0) + 1
    
    # Convertir en tableau et trier par fréquence
    return sorted(
        [[int(factor), count] for factor, count in factor_count.items()],
        key=lambda x: x[1],
        reverse=True
    )


def kasiski_examination(text):
    """
    Examen de Kasiski amélioré:
    Recherche de substrings répétés (3-6 lettres) et calcul des positions.
    """
    # Nettoyer le texte et convertir en majuscules
    cleaned = re.sub(r'[^A-Z]', '', text.upper())
    results = []
    found_sequences = set()
    
    # Rechercher des séquences de 3 à 6 caractères
    for size in range(3, min(7, math.floor(len(cleaned) / 2) + 1)):
        for i in range(0, len(cleaned) - size + 1):
            seq = cleaned[i:i + size]
            
            # Ignorer les séquences déjà trouvées ou trop répétitives
            if seq in found_sequences or re.match(r'^(.)\1+$', seq):
                continue
            
            # Chercher toutes les occurrences de cette séquence
            positions = []
            for j in range(0, len(cleaned) - size + 1):
                if cleaned[j:j + size] == seq:
                    positions.append(j)
            
            # Si au moins 2 occurrences trouvées
            if len(positions) >= 2:
                found_sequences.add(seq)
                results.append({"seq": seq, "positions": positions})
    
    # Trier par longueur de séquence (plus longues d'abord) puis par nombre d'occurrences
    results.sort(key=lambda x: (-len(x["seq"]), -len(x["positions"])))
    
    return results


def display_kasiski_results(kasiski_res):
    """
    Affichage amélioré des résultats Kasiski
    """
    result = "EXAMEN DE KASISKI\n"
    result += "=================\n\n"

    if not kasiski_res:
        result += "Aucune séquence répétée trouvée.\n"
        result += "Le texte pourrait être:\n"
        result += "- Chiffré avec une clé très longue\n"
        result += "- Chiffré avec un algorithme non-périodique\n"
        result += "- Trop court pour l'analyse\n"
    else:
        result += f"{len(kasiski_res)} séquence(s) répétée(s) trouvée(s):\n\n"
        
        all_distances = []
        
        for index, item in enumerate(kasiski_res):
            result += f"{index + 1}. \"{item['seq']}\" ({len(item['seq'])} lettres)\n"
            result += f"   Positions: {', '.join(map(str, item['positions']))}\n"
            
            # Calculer toutes les distances
            distances = []
            for i in range(len(item['positions'])):
                for j in range(i + 1, len(item['positions'])):
                    distance = item['positions'][j] - item['positions'][i]
                    distances.append(distance)
                    all_distances.append(distance)
            
            if distances:
                result += f"   Distances: {', '.join(map(str, distances))}\n"
            result += "\n"

        # Analyse des longueurs de clé probables
        if all_distances:
            gcd = calculate_gcd(all_distances)
            factor_analysis = analyze_factors(all_distances)
            
            result += "ANALYSE DES DISTANCES:\n"
            result += "----------------------\n"
            result += f"Toutes les distances: {', '.join(map(str, sorted(all_distances)))}\n"
            result += f"PGCD: {gcd}\n\n"
            
            result += "Longueurs de clé probables:\n"
            for factor, count in factor_analysis[:8]:  # Afficher les 8 premiers résultats
                percentage = (count / len(all_distances)) * 100
                result += f"{factor}: {count}/{len(all_distances)} ({percentage:.1f}%)\n"

    return result


def main():
    parser = argparse.ArgumentParser(description="Examen de Kasiski pour l'analyse cryptographique.")
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
    
    # Exécuter l'examen de Kasiski et afficher les résultats
    kasiski_res = kasiski_examination(text)
    result = display_kasiski_results(kasiski_res)
    print(result)


if __name__ == "__main__":
    main()