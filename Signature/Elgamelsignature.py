#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
elgamelsignature_enhanced.py - Implémentation de la signature numérique ElGamal

Ce script implémente un système de signature numérique ElGamal.
Il permet de générer des clés, signer et vérifier des messages.
Il offre également des options pour sauvegarder/charger des clés et définir manuellement les paramètres.
"""

import hashlib
import random
import json
import sys
import os


class ElGamalSignature:
    """
    Classe implémentant les primitives cryptographiques nécessaires pour la signature ElGamal.
    """
    
    @staticmethod
    def is_prime(n, k=5):
        """Test de primalité de Miller-Rabin"""
        if n <= 1 or n == 4:
            return False
        if n <= 3:
            return True
        
        # Trouver r et d tels que n-1 = 2^r * d
        d = n - 1
        r = 0
        while d % 2 == 0:
            d //= 2
            r += 1
        
        # Effectuer k tests
        for _ in range(k):
            a = random.randint(2, n - 2)
            x = pow(a, d, n)
            if x == 1 or x == n - 1:
                continue
            for _ in range(r - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    break
            else:
                return False
        return True
    
    @staticmethod
    def generate_prime(min_val, max_val):
        """
        Génère un nombre premier dans l'intervalle [min_val, max_val].
        """
        while True:
            p = random.randint(min_val, max_val)
            # S'assurer que c'est impair
            if p % 2 == 0:
                p += 1
            if ElGamalSignature.is_prime(p):
                return p
    
    @staticmethod
    def find_generator(p):
        """Trouve un générateur g pour le groupe multiplicatif Z_p*"""
        if p == 2:
            return 1
        
        # Pour simplifier, on vérifie que g^((p-1)/2) != 1 mod p
        # et g^((p-1)) == 1 mod p
        for g in range(2, p):
            if pow(g, (p-1) // 2, p) != 1 and pow(g, p-1, p) == 1:
                return g
        
        # Fallback (ne devrait pas arriver avec un p premier)
        return 2
    
    @staticmethod
    def gcd(a, b):
        """Calcule le PGCD de deux nombres"""
        while b:
            a, b = b, a % b
        return a
    
    @staticmethod
    def extended_gcd(a, b):
        """Algorithme d'Euclide étendu"""
        if a == 0:
            return b, 0, 1
        gcd, x1, y1 = ElGamalSignature.extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        return gcd, x, y
    
    @staticmethod
    def mod_inverse(a, m):
        """Calcule l'inverse modulaire de a modulo m"""
        gcd, x, _ = ElGamalSignature.extended_gcd(a, m)
        if gcd != 1:
            raise Exception('Modular inverse does not exist')
        else:
            return (x % m + m) % m
    
    @staticmethod
    def prime_factors(n):
        """
        Factorisation d'un nombre en ses facteurs premiers.
        """
        factors = []
        i = 2
        while i * i <= n:
            while n % i == 0:
                factors.append(i)
                n //= i
            i += 1
        if n > 1:
            factors.append(n)
        return list(set(factors))  # Facteurs uniques
    
    @staticmethod
    def hash_message(message):
        """Calcule le hachage SHA-256 d'un message"""
        if isinstance(message, str):
            message = message.encode('utf-8')
        return int.from_bytes(hashlib.sha256(message).digest(), byteorder='big')


def generate_keypair(min_prime=1000, max_prime=10000):
    """Génère une paire de clés ElGamal pour la signature"""
    print(f"Génération d'une paire de clés ElGamal (p dans [{min_prime}, {max_prime}])...")
    
    # Générer un nombre premier p
    p = ElGamalSignature.generate_prime(min_prime, max_prime)
    
    # Trouver un générateur g du groupe multiplicatif Z_p*
    g = ElGamalSignature.find_generator(p)
    
    # Clé privée aléatoire x, 1 < x < p-1
    x = random.randint(2, p-2)
    
    # Calculer la clé publique y = g^x mod p
    y = pow(g, x, p)
    
    print("Paire de clés générée avec succès!")
    
    return {
        'p': p,
        'g': g,
        'y': y,
        'x': x
    }


def sign(message, keys):
    """Signe un message avec la clé privée ElGamal"""
    p, g, x = keys['p'], keys['g'], keys['x']
    h = ElGamalSignature.hash_message(message) % p
    
    # Choisir un k aléatoire tel que gcd(k, p-1) = 1
    while True:
        k = random.randint(2, p-2)
        if ElGamalSignature.gcd(k, p-1) == 1:
            break
    
    # Calculer r = g^k mod p
    r = pow(g, k, p)
    
    # Calculer s = (h - x*r) * k^(-1) mod (p-1)
    k_inv = ElGamalSignature.mod_inverse(k, p-1)
    s = (h - x * r) * k_inv % (p-1)
    
    return (r, s)


def verify(message, signature, keys):
    """Vérifie une signature avec la clé publique ElGamal"""
    p, g, y = keys['p'], keys['g'], keys['y']
    r, s = signature
    
    # Vérifier que 0 < r < p et 0 < s < p-1
    if r <= 0 or r >= p or s <= 0 or s >= p-1:
        return False
    
    h = ElGamalSignature.hash_message(message) % p
    
    # Vérifier que g^h = y^r * r^s mod p
    left = pow(g, h, p)
    right = (pow(y, r, p) * pow(r, s, p)) % p
    
    return left == right


def save_keys(keys, private_key_file="elgamal_signature_private.json", public_key_file="elgamal_signature_public.json"):
    """
    Enregistre les clés ElGamal dans des fichiers JSON.
    """
    # Préparation des dictionnaires à sauvegarder
    private_key_data = {
        'p': keys['p'],
        'g': keys['g'],
        'x': keys['x']
    }
    
    public_key_data = {
        'p': keys['p'],
        'g': keys['g'],
        'y': keys['y']
    }
    
    # Enregistrement des clés dans des fichiers JSON
    with open(private_key_file, "w") as private_file:
        json.dump(private_key_data, private_file)
    
    with open(public_key_file, "w") as public_file:
        json.dump(public_key_data, public_file)
    
    print(f"Clés enregistrées dans '{private_key_file}' et '{public_key_file}'")


def load_keys_from_files(private_key_file="elgamal_signature_private.json", public_key_file="elgamal_signature_public.json"):
    """
    Charge les clés ElGamal à partir de fichiers JSON.
    """
    try:
        # Chargement de la clé privée
        with open(private_key_file, "r") as private_file:
            private_key_data = json.load(private_file)
        
        # Chargement de la clé publique
        with open(public_key_file, "r") as public_file:
            public_key_data = json.load(public_file)
        
        # Vérification de la cohérence des clés
        if (private_key_data['p'] != public_key_data['p'] or 
            private_key_data['g'] != public_key_data['g']):
            raise ValueError("Les clés privée et publique ne sont pas compatibles")
        
        # Construction du dictionnaire de clés complet
        keys = {
            'p': private_key_data['p'],
            'g': private_key_data['g'],
            'x': private_key_data['x'],
            'y': public_key_data['y']
        }
        
        print(f"Clés chargées avec succès depuis '{private_key_file}' et '{public_key_file}'")
        return keys
    
    except Exception as e:
        print(f"Erreur lors du chargement des clés: {e}")
        return None


def create_keys_from_components(p, g, x=None, y=None):
    """
    Crée une paire de clés ElGamal à partir des composants mathématiques.
    """
    try:
        # Vérification que p est premier
        if not ElGamalSignature.is_prime(p):
            raise ValueError("p doit être un nombre premier")
        
        # Vérification que g est un générateur valide
        if g <= 1 or g >= p:
            raise ValueError("g doit être dans l'intervalle [2, p-1]")
        
        # Si x et y sont tous les deux fournis, vérifier qu'ils sont cohérents
        if x is not None and y is not None:
            calculated_y = pow(g, x, p)
            if calculated_y != y:
                raise ValueError("Les valeurs x et y ne sont pas cohérentes (y != g^x mod p)")
        
        # Si seul x est fourni, calculer y
        elif x is not None:
            if x <= 0 or x >= p:
                raise ValueError("x doit être dans l'intervalle [1, p-1]")
            y = pow(g, x, p)
        
        # Si seul y est fourni, impossible de retrouver x (problème du logarithme discret)
        elif y is not None:
            if y <= 0 or y >= p:
                raise ValueError("y doit être dans l'intervalle [1, p-1]")
            # Générer un x temporaire
            x = random.randint(1, p - 2)
            y_calc = pow(g, x, p)
            print(f"ATTENTION: x a été généré aléatoirement car impossible de calculer x à partir de y.")
            print(f"La valeur y fournie ({y}) ne sera pas utilisée. Valeur y calculée: {y_calc}")
            y = y_calc
        
        # Si ni x ni y ne sont fournis, générer x aléatoirement et calculer y
        else:
            x = random.randint(1, p - 2)
            y = pow(g, x, p)
        
        keys = {
            'p': p,
            'g': g,
            'x': x,
            'y': y
        }
        
        print("Clés créées avec succès à partir des composants!")
        return keys
    
    except Exception as e:
        print(f"Erreur lors de la création des clés à partir des composants: {e}")
        return None


def display_key_components(keys):
    """
    Affiche les composants des clés ElGamal pour la signature.
    """
    print("\n=== Composants des clés ElGamal pour la signature ===")
    print(f"Nombre premier (p): {keys['p']}")
    print(f"Générateur (g): {keys['g']}")
    print(f"Clé publique (y = g^x mod p): {keys['y']}")
    print(f"Clé privée (x): {keys['x']}")
    
    # Vérification
    y_calc = pow(keys['g'], keys['x'], keys['p'])
    print(f"Vérification: g^x mod p = y? {y_calc == keys['y']}")


def main():
    """Fonction principale du programme"""
    print("=" * 80)
    print("SYSTÈME DE SIGNATURE NUMÉRIQUE ELGAMAL")
    print("=" * 80)
    
    # Variable pour stocker les clés
    keys = None
    
    # Demander à l'utilisateur comment il souhaite obtenir les clés
    key_choice = input("\nComment souhaitez-vous obtenir les clés ElGamal?\n"
                      "1. Générer de nouvelles clés\n"
                      "2. Charger des clés depuis des fichiers\n"
                      "3. Entrer les composants manuellement (p, g, x, y)\n"
                      "Votre choix (1/2/3): ")
    
    if key_choice == "3":
        # Entrée manuelle des composants
        print("\nVeuillez entrer les composants des clés ElGamal:")
        try:
            # Conversion en entiers pour les grands nombres
            p = int(input("Nombre premier (p): "))
            g = int(input("Générateur (g): "))
            
            x_input = input("Clé privée (x) (optionnel, appuyez sur Entrée pour passer): ")
            y_input = input("Clé publique (y) (optionnel, appuyez sur Entrée pour passer): ")
            
            x = int(x_input) if x_input else None
            y = int(y_input) if y_input else None
            
            keys = create_keys_from_components(p, g, x, y)
            
            if keys is None:
                print("Impossible de continuer sans clés valides. Le programme va s'arrêter.")
                return
        except ValueError as e:
            print(f"Erreur de conversion: {e}")
            return
    
    elif key_choice == "2":
        # Utiliser des clés existantes
        private_key_file = input("Chemin vers le fichier de clé privée (par défaut: elgamal_signature_private.json): ") or "elgamal_signature_private.json"
        public_key_file = input("Chemin vers le fichier de clé publique (par défaut: elgamal_signature_public.json): ") or "elgamal_signature_public.json"
        
        keys = load_keys_from_files(private_key_file, public_key_file)
        
        if keys is None:
            print("Impossible de continuer sans clés valides. Le programme va s'arrêter.")
            return
    else:
        # Génération des clés ElGamal (option par défaut)
        min_prime = int(input("Valeur minimale pour p (par défaut: 1000): ") or "1000")
        max_prime = int(input("Valeur maximale pour p (par défaut: 10000): ") or "10000")
        
        keys = generate_keypair(min_prime, max_prime)
        
        # Option pour sauvegarder les clés
        save_keys_option = input("Voulez-vous sauvegarder les clés? (o/n): ").lower()
        if save_keys_option == 'o' or save_keys_option == 'oui':
            private_key_file = input("Nom du fichier pour la clé privée (par défaut: elgamal_signature_private.json): ") or "elgamal_signature_private.json"
            public_key_file = input("Nom du fichier pour la clé publique (par défaut: elgamal_signature_public.json): ") or "elgamal_signature_public.json"
            save_keys(keys, private_key_file, public_key_file)
    
    # Afficher les composants des clés ElGamal
    display_choice = input("Voulez-vous afficher les composants des clés (p, g, y, x)? (o/n): ").lower()
    if display_choice == 'o' or display_choice == 'oui':
        display_key_components(keys)
    
    # Menu principal pour les opérations
    while True:
        print("\n=== Menu principal ===")
        print("1. Signer un message")
        print("2. Vérifier une signature")
        print("3. Générer de nouvelles clés")
        print("4. Afficher les clés actuelles")
        print("5. Quitter")
        
        choice = input("\nVotre choix (1-5): ").strip()
        
        if choice == "1":
            # Signature
            message = input("\nEntrez le message à signer: ")
            if not message:
                print("Message vide, opération annulée.")
                continue
            
            try:
                signature = sign(message, keys)
                print(f"\nMessage signé avec succès!")
                print(f"Signature (r, s): {signature}")
                print(f"r = {signature[0]}")
                print(f"s = {signature[1]}")
            except Exception as e:
                print(f"\n❌ Erreur de signature: {e}")
            
        elif choice == "2":
            # Vérification
            message = input("\nEntrez le message à vérifier: ")
            if not message:
                print("Message vide, opération annulée.")
                continue
            
            try:
                r = int(input("Entrez la composante r de la signature: "))
                s = int(input("Entrez la composante s de la signature: "))
                signature = (r, s)
                
                if verify(message, signature, keys):
                    print("\n✅ Vérification réussie: La signature est valide!")
                else:
                    print("\n❌ Échec de la vérification: La signature est invalide!")
            except ValueError as e:
                print(f"\n❌ Erreur: {e}")
                
        elif choice == "3":
            # Régénération des clés
            min_prime = int(input("Valeur minimale pour p (par défaut: 1000): ") or "1000")
            max_prime = int(input("Valeur maximale pour p (par défaut: 10000): ") or "10000")
            
            keys = generate_keypair(min_prime, max_prime)
            
            # Option pour sauvegarder les clés
            save_keys_option = input("Voulez-vous sauvegarder les clés? (o/n): ").lower()
            if save_keys_option == 'o' or save_keys_option == 'oui':
                private_key_file = input("Nom du fichier pour la clé privée (par défaut: elgamal_signature_private.json): ") or "elgamal_signature_private.json"
                public_key_file = input("Nom du fichier pour la clé publique (par défaut: elgamal_signature_public.json): ") or "elgamal_signature_public.json"
                save_keys(keys, private_key_file, public_key_file)
            
            display_key_components(keys)
            
        elif choice == "4":
            # Afficher les clés
            if keys:
                display_key_components(keys)
            else:
                print("Aucune clé disponible.")
            
        elif choice == "5":
            # Quitter
            print("\nAu revoir!")
            break
            
        else:
            print("\nOption invalide. Veuillez choisir entre 1 et 5.")
    
    print("\n" + "=" * 80)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nOpération interrompue par l'utilisateur.")
    except Exception as e:
        print(f"\n❌ Erreur: {e}")