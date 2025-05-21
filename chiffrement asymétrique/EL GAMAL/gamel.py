#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
elgamal_crypto.py - Implémentation d'un cryptosystème ElGamal

Ce script implémente un système de chiffrement ElGamal.
Il permet de générer des clés, chiffrer et déchiffrer un message fourni par l'utilisateur.
Il offre également des options pour sauvegarder/charger des clés et définir manuellement les paramètres.
"""

import random
import base64
import math
import json
import os


class ElGamalCrypto:
    """
    Classe implémentant les primitives cryptographiques nécessaires pour ElGamal.
    """
    
    @staticmethod
    def is_prime(n, k=5):
        """
        Test de primalité de Miller-Rabin.
        
        Args:
            n (int): Nombre à tester
            k (int): Nombre d'itérations pour le test (plus k est grand, plus le test est fiable)
        
        Returns:
            bool: True si n est probablement premier, False sinon
        """
        if n < 2:
            return False
        if n == 2 or n == 3:
            return True
        if n % 2 == 0:
            return False
        
        # Écrire n-1 comme d * 2^r
        r, d = 0, n - 1
        while d % 2 == 0:
            d //= 2
            r += 1
        
        # Test de Miller-Rabin k fois
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
        
        Args:
            min_val (int): Valeur minimale
            max_val (int): Valeur maximale
        
        Returns:
            int: Un nombre premier dans l'intervalle spécifié
        """
        while True:
            candidate = random.randint(min_val, max_val)
            # S'assurer que c'est impair
            if candidate % 2 == 0:
                candidate += 1
            if ElGamalCrypto.is_prime(candidate):
                return candidate
    
    @staticmethod
    def mod_pow(base, exponent, modulus):
        """
        Exponentiation modulaire rapide (base^exponent mod modulus).
        
        Args:
            base (int): Base
            exponent (int): Exposant
            modulus (int): Modulo
        
        Returns:
            int: Résultat de l'exponentiation modulaire
        """
        if modulus == 1:
            return 0
        result = 1
        base = base % modulus
        while exponent > 0:
            if exponent % 2 == 1:
                result = (result * base) % modulus
            exponent = exponent >> 1  # Division par 2
            base = (base * base) % modulus
        return result
    
    @staticmethod
    def extended_gcd(a, b):
        """
        Algorithme d'Euclide étendu.
        
        Args:
            a (int): Premier nombre
            b (int): Deuxième nombre
        
        Returns:
            tuple: (gcd, x, y) tels que gcd = ax + by
        """
        if a == 0:
            return b, 0, 1
        gcd, x1, y1 = ElGamalCrypto.extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        return gcd, x, y
    
    @staticmethod
    def mod_inverse(a, m):
        """
        Calcule l'inverse modulaire de a modulo m.
        
        Args:
            a (int): Nombre dont on cherche l'inverse
            m (int): Modulo
        
        Returns:
            int: Inverse modulaire de a
        """
        gcd, x, _ = ElGamalCrypto.extended_gcd(a, m)
        if gcd != 1:
            return None  # Pas d'inverse
        return (x % m + m) % m
    
    @staticmethod
    def find_generator(p):
        """
        Trouve un générateur du groupe multiplicatif modulo p.
        
        Args:
            p (int): Nombre premier
        
        Returns:
            int: Un générateur du groupe
        """
        phi = p - 1
        factors = ElGamalCrypto.prime_factors(phi)
        
        # Tester des valeurs potentielles de g
        for g in range(2, p):
            is_generator = True
            for factor in factors:
                if ElGamalCrypto.mod_pow(g, phi // factor, p) == 1:
                    is_generator = False
                    break
            if is_generator:
                return g
        
        # Fallback, mais cela ne devrait pas arriver avec un p premier
        return 2
    
    @staticmethod
    def prime_factors(n):
        """
        Factorisation d'un nombre en ses facteurs premiers.
        
        Args:
            n (int): Nombre à factoriser
        
        Returns:
            list: Liste des facteurs premiers uniques
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
    def text_to_numbers(text):
        """
        Convertit un texte en liste de valeurs numériques.
        
        Args:
            text (str): Texte à convertir
        
        Returns:
            list: Liste des codes ASCII des caractères
        """
        return [ord(char) for char in text]
    
    @staticmethod
    def numbers_to_text(numbers):
        """
        Convertit une liste de valeurs numériques en texte.
        
        Args:
            numbers (list): Liste des codes ASCII
        
        Returns:
            str: Texte correspondant
        """
        return ''.join([chr(num) for num in numbers])


def generate_elgamal_keys(min_prime=1000, max_prime=2000):
    """
    Génère une paire de clés ElGamal.
    
    Args:
        min_prime (int): Valeur minimale pour le nombre premier p
        max_prime (int): Valeur maximale pour le nombre premier p
    
    Returns:
        dict: Les clés ElGamal (p, g, y, x)
    """
    print(f"Génération d'une paire de clés ElGamal (p dans [{min_prime}, {max_prime}])...")
    
    # Générer un nombre premier p
    p = ElGamalCrypto.generate_prime(min_prime, max_prime)
    
    # Trouver un générateur g
    g = ElGamalCrypto.find_generator(p)
    
    # Clé privée aléatoire x
    x = random.randint(1, p - 2)
    
    # Clé publique y = g^x mod p
    y = ElGamalCrypto.mod_pow(g, x, p)
    
    print("Paire de clés générée avec succès!")
    
    return {
        'p': p,
        'g': g,
        'y': y,
        'x': x
    }


def encrypt_elgamal(message, keys):
    """
    Chiffre un message avec ElGamal.
    
    Args:
        message (str): Le message en clair à chiffrer
        keys (dict): Les clés ElGamal
    
    Returns:
        list: Liste des paires (c1, c2) pour chaque caractère
    """
    print("Chiffrement du message avec la clé publique...")
    
    p, g, y = keys['p'], keys['g'], keys['y']
    message_numbers = ElGamalCrypto.text_to_numbers(message)
    ciphertext = []
    
    for m in message_numbers:
        # Vérifier que le message est dans la plage valide
        if m >= p:
            raise ValueError(f"Caractère '{chr(m)}' trop grand pour p={p}")
        
        # Générer k aléatoire pour chaque caractère
        k = random.randint(1, p - 2)
        
        # Calculer c1 = g^k mod p
        c1 = ElGamalCrypto.mod_pow(g, k, p)
        
        # Calculer c2 = m * y^k mod p
        c2 = (m * ElGamalCrypto.mod_pow(y, k, p)) % p
        
        ciphertext.append((c1, c2))
    
    return ciphertext


def decrypt_elgamal(ciphertext, keys):
    """
    Déchiffre un message chiffré avec ElGamal.
    
    Args:
        ciphertext (list): Liste des paires (c1, c2)
        keys (dict): Les clés ElGamal
    
    Returns:
        str: Le message déchiffré
    """
    print("Déchiffrement du message avec la clé privée...")
    
    p, x = keys['p'], keys['x']
    decrypted_numbers = []
    
    for c1, c2 in ciphertext:
        # Calculer s = c1^x mod p
        s = ElGamalCrypto.mod_pow(c1, x, p)
        
        # Calculer l'inverse de s
        s_inv = ElGamalCrypto.mod_inverse(s, p)
        
        if s_inv is None:
            raise ValueError("Impossible de calculer l'inverse modulaire")
        
        # Récupérer le message m = c2 * s^(-1) mod p
        m = (c2 * s_inv) % p
        
        decrypted_numbers.append(m)
    
    return ElGamalCrypto.numbers_to_text(decrypted_numbers)


def serialize_ciphertext(ciphertext):
    """
    Convertit le texte chiffré en chaîne de caractères.
    
    Args:
        ciphertext (list): Liste des paires (c1, c2)
    
    Returns:
        str: Texte chiffré sérialisé et encodé en base64
    """
    ciphertext_str = json.dumps(ciphertext)
    return base64.b64encode(ciphertext_str.encode('utf-8')).decode('utf-8')


def deserialize_ciphertext(serialized):
    """
    Convertit une chaîne de caractères en texte chiffré.
    
    Args:
        serialized (str): Texte chiffré sérialisé et encodé en base64
    
    Returns:
        list: Liste des paires (c1, c2)
    """
    try:
        ciphertext_str = base64.b64decode(serialized).decode('utf-8')
        return json.loads(ciphertext_str)
    except:
        raise ValueError("Format de texte chiffré invalide")


def save_keys(keys, private_key_file="elgamal_private_key.json", public_key_file="elgamal_public_key.json"):
    """
    Enregistre les clés ElGamal dans des fichiers JSON.
    
    Args:
        keys (dict): Les clés ElGamal
        private_key_file (str): Nom du fichier pour la clé privée
        public_key_file (str): Nom du fichier pour la clé publique
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


def load_keys_from_files(private_key_file="elgamal_private_key.json", public_key_file="elgamal_public_key.json"):
    """
    Charge les clés ElGamal à partir de fichiers JSON.
    
    Args:
        private_key_file (str): Chemin vers le fichier de clé privée
        public_key_file (str): Chemin vers le fichier de clé publique
        
    Returns:
        dict: Les clés ElGamal ou None en cas d'erreur
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
    
    Args:
        p (int): Nombre premier
        g (int): Générateur
        x (int, optional): Clé privée
        y (int, optional): Clé publique
    
    Returns:
        dict: Les clés ElGamal ou None en cas d'erreur
    """
    try:
        # Vérification que p est premier
        if not ElGamalCrypto.is_prime(p):
            raise ValueError("p doit être un nombre premier")
        
        # Vérification que g est un générateur valide
        if g <= 1 or g >= p:
            raise ValueError("g doit être dans l'intervalle [2, p-1]")
        
        # Si x et y sont tous les deux fournis, vérifier qu'ils sont cohérents
        if x is not None and y is not None:
            calculated_y = ElGamalCrypto.mod_pow(g, x, p)
            if calculated_y != y:
                raise ValueError("Les valeurs x et y ne sont pas cohérentes (y != g^x mod p)")
        
        # Si seul x est fourni, calculer y
        elif x is not None:
            if x <= 0 or x >= p:
                raise ValueError("x doit être dans l'intervalle [1, p-1]")
            y = ElGamalCrypto.mod_pow(g, x, p)
        
        # Si seul y est fourni, impossible de retrouver x (problème du logarithme discret)
        elif y is not None:
            if y <= 0 or y >= p:
                raise ValueError("y doit être dans l'intervalle [1, p-1]")
            # Générer un x temporaire
            x = random.randint(1, p - 2)
            y_calc = ElGamalCrypto.mod_pow(g, x, p)
            print(f"ATTENTION: x a été généré aléatoirement car impossible de calculer x à partir de y.")
            print(f"La valeur y fournie ({y}) ne sera pas utilisée. Valeur y calculée: {y_calc}")
            y = y_calc
        
        # Si ni x ni y ne sont fournis, générer x aléatoirement et calculer y
        else:
            x = random.randint(1, p - 2)
            y = ElGamalCrypto.mod_pow(g, x, p)
        
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
    Affiche les composants des clés ElGamal.
    
    Args:
        keys (dict): Les clés ElGamal
    """
    print("\n=== Composants des clés ElGamal ===")
    print(f"Nombre premier (p): {keys['p']}")
    print(f"Générateur (g): {keys['g']}")
    print(f"Clé publique (y = g^x mod p): {keys['y']}")
    print(f"Clé privée (x): {keys['x']}")
    
    # Vérification
    y_calc = ElGamalCrypto.mod_pow(keys['g'], keys['x'], keys['p'])
    print(f"Vérification: g^x mod p = y? {y_calc == keys['y']}")


def main():
    """Fonction principale du programme"""
    print("=" * 80)
    print("SYSTÈME DE CHIFFREMENT ELGAMAL")
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
        private_key_file = input("Chemin vers le fichier de clé privée (par défaut: elgamal_private_key.json): ") or "elgamal_private_key.json"
        public_key_file = input("Chemin vers le fichier de clé publique (par défaut: elgamal_public_key.json): ") or "elgamal_public_key.json"
        
        keys = load_keys_from_files(private_key_file, public_key_file)
        
        if keys is None:
            print("Impossible de continuer sans clés valides. Le programme va s'arrêter.")
            return
    else:
        # Génération des clés ElGamal (option par défaut)
        min_prime = int(input("Valeur minimale pour p (par défaut: 1000): ") or "1000")
        max_prime = int(input("Valeur maximale pour p (par défaut: 2000): ") or "2000")
        
        keys = generate_elgamal_keys(min_prime, max_prime)
        
        # Option pour sauvegarder les clés
        save_keys_option = input("Voulez-vous sauvegarder les clés? (o/n): ").lower()
        if save_keys_option == 'o' or save_keys_option == 'oui':
            private_key_file = input("Nom du fichier pour la clé privée (par défaut: elgamal_private_key.json): ") or "elgamal_private_key.json"
            public_key_file = input("Nom du fichier pour la clé publique (par défaut: elgamal_public_key.json): ") or "elgamal_public_key.json"
            save_keys(keys, private_key_file, public_key_file)
    
    # Afficher les composants des clés ElGamal
    display_choice = input("Voulez-vous afficher les composants des clés (p, g, y, x)? (o/n): ").lower()
    if display_choice == 'o' or display_choice == 'oui':
        display_key_components(keys)
    
    # Menu principal pour les opérations
    while True:
        print("\n=== Menu principal ===")
        print("1. Chiffrer un message")
        print("2. Déchiffrer un message")
        print("3. Générer de nouvelles clés")
        print("4. Afficher les clés actuelles")
        print("5. Quitter")
        
        choice = input("\nVotre choix (1-5): ").strip()
        
        if choice == "1":
            # Chiffrement
            plaintext = input("\nEntrez le message à chiffrer: ")
            if not plaintext:
                print("Message vide, opération annulée.")
                continue
            
            try:
                ciphertext = encrypt_elgamal(plaintext, keys)
                serialized = serialize_ciphertext(ciphertext)
                print(f"\nMessage chiffré (Base64): {serialized}")
            except Exception as e:
                print(f"\n❌ Erreur de chiffrement: {e}")
            
        elif choice == "2":
            # Déchiffrement
            serialized = input("\nEntrez le message chiffré (Base64): ")
            if not serialized:
                print("Message vide, opération annulée.")
                continue
            
            try:
                ciphertext = deserialize_ciphertext(serialized)
                decrypted_text = decrypt_elgamal(ciphertext, keys)
                print(f"\nMessage déchiffré: {decrypted_text}")
                
                # Vérification d'intégrité
                verify_choice = input("\nVoulez-vous vérifier en chiffrant à nouveau ce message? (o/n): ").lower()
                if verify_choice == 'o' or verify_choice == 'oui':
                    new_ciphertext = encrypt_elgamal(decrypted_text, keys)
                    new_serialized = serialize_ciphertext(new_ciphertext)
                    if new_serialized != serialized:
                        print("Note: Le nouveau chiffré est différent de l'original (normal car k est aléatoire).")
            except Exception as e:
                print(f"\n❌ Erreur de déchiffrement: {e}")
                
        elif choice == "3":
            # Régénération des clés
            min_prime = int(input("Valeur minimale pour p (par défaut: 1000): ") or "1000")
            max_prime = int(input("Valeur maximale pour p (par défaut: 2000): ") or "2000")
            
            keys = generate_elgamal_keys(min_prime, max_prime)
            
            # Option pour sauvegarder les clés
            save_keys_option = input("Voulez-vous sauvegarder les clés? (o/n): ").lower()
            if save_keys_option == 'o' or save_keys_option == 'oui':
                private_key_file = input("Nom du fichier pour la clé privée (par défaut: elgamal_private_key.json): ") or "elgamal_private_key.json"
                public_key_file = input("Nom du fichier pour la clé publique (par défaut: elgamal_public_key.json): ") or "elgamal_public_key.json"
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