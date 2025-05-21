#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
RSA Signature Implementation - Version améliorée
"""

import hashlib
import random
import math
import sys
import json
import base64

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

def generate_prime(bits):
    """Génère un nombre premier de taille bits"""
    while True:
        p = random.getrandbits(bits)
        # Assurer que p est impair
        p |= 1
        if is_prime(p):
            return p

def gcd(a, b):
    """Calcule le PGCD de deux nombres"""
    while b:
        a, b = b, a % b
    return a

def mod_inverse(e, phi):
    """Calcule l'inverse modulaire de e modulo phi"""
    def extended_gcd(a, b):
        if a == 0:
            return b, 0, 1
        else:
            gcd, x, y = extended_gcd(b % a, a)
            return gcd, y - (b // a) * x, x
    
    g, x, y = extended_gcd(e, phi)
    if g != 1:
        raise Exception('L\'inverse modulaire n\'existe pas')
    else:
        return x % phi

def generate_keypair(bits=1024):
    """Génère une paire de clés RSA"""
    print(f"Génération d'une paire de clés RSA ({bits} bits)...")
    
    p = generate_prime(bits // 2)
    q = generate_prime(bits // 2)
    n = p * q
    phi = (p - 1) * (q - 1)
    
    # Choisir e tel que e et phi sont premiers entre eux
    e = 65537  # Valeur couramment utilisée pour e
    while gcd(e, phi) != 1:
        e = random.randrange(2, phi)
    
    # Calculer d tel que (d * e) % phi = 1
    d = mod_inverse(e, phi)
    
    print("Paire de clés générée avec succès!")
    
    return {"public": (e, n), "private": (d, n)}

def hash_message(message):
    """Calcule le hachage SHA-256 d'un message"""
    if isinstance(message, str):
        message = message.encode('utf-8')
    return int.from_bytes(hashlib.sha256(message).digest(), byteorder='big')

def sign(message, private_key):
    """Signe un message avec la clé privée RSA"""
    print("Signature du message en cours...")
    
    d, n = private_key
    h = hash_message(message)
    
    # Vérifier que le hash est plus petit que n
    if h >= n:
        raise ValueError("Le hash du message est trop grand pour cette clé RSA")
    
    # S = H(M)^d mod n
    signature = pow(h, d, n)
    print("Message signé avec succès!")
    
    return signature

def verify(message, signature, public_key):
    """Vérifie une signature avec la clé publique RSA"""
    print("Vérification de la signature en cours...")
    
    e, n = public_key
    h = hash_message(message)
    
    # H(M) = S^e mod n
    decrypted_hash = pow(signature, e, n)
    
    return h == decrypted_hash

def save_keys(keys, private_key_file="rsa_signature_private.json", public_key_file="rsa_signature_public.json"):
    """Enregistre les clés RSA dans des fichiers JSON."""
    # Préparation des dictionnaires à sauvegarder
    e, n = keys["public"]
    d, _ = keys["private"]
    
    private_key_data = {
        "d": d,
        "n": n
    }
    
    public_key_data = {
        "e": e,
        "n": n
    }
    
    # Enregistrement des clés dans des fichiers JSON
    with open(private_key_file, "w") as private_file:
        json.dump(private_key_data, private_file)
    
    with open(public_key_file, "w") as public_file:
        json.dump(public_key_data, public_file)
    
    print(f"Clés enregistrées dans '{private_key_file}' et '{public_key_file}'")

def load_keys_from_files(private_key_file="rsa_signature_private.json", public_key_file="rsa_signature_public.json"):
    """Charge les clés RSA à partir de fichiers JSON."""
    try:
        # Chargement de la clé privée
        with open(private_key_file, "r") as private_file:
            private_key_data = json.load(private_file)
        
        # Chargement de la clé publique
        with open(public_key_file, "r") as public_file:
            public_key_data = json.load(public_file)
        
        # Construction du dictionnaire de clés complet
        keys = {
            "public": (public_key_data["e"], public_key_data["n"]),
            "private": (private_key_data["d"], private_key_data["n"])
        }
        
        print(f"Clés chargées avec succès depuis '{private_key_file}' et '{public_key_file}'")
        return keys
    
    except Exception as e:
        print(f"Erreur lors du chargement des clés: {e}")
        return None

def create_keys_from_components(e=None, d=None, n=None):
    """Crée une paire de clés RSA à partir des composants mathématiques."""
    try:
        if n is None:
            raise ValueError("Le module n est requis")
        
        if e is None and d is None:
            raise ValueError("Au moins l'un des exposants (e ou d) est requis")
        
        # Si e est fourni mais pas d, essayer de calculer d
        if e is not None and d is None:
            # On ne peut pas calculer d sans connaître phi(n), qui nécessite
            # la factorisation de n (problème difficile)
            raise ValueError("Impossible de déduire d à partir de e sans les facteurs de n")
        
        # Si d est fourni mais pas e, essayer de générer un e valide
        if d is not None and e is None:
            # On peut essayer de choisir un e classique (65537) et vérifier sa compatibilité
            e = 65537
            # Mais sans phi(n), on ne peut pas vérifier gcd(e, phi) == 1
            print("ATTENTION: Sans connaître la factorisation de n, on ne peut pas garantir que e et d sont inverses l'un de l'autre")
        
        # Construire les clés
        public_key = (e, n)
        private_key = (d, n)
        
        keys = {
            "public": public_key,
            "private": private_key
        }
        
        print("Clés créées avec succès à partir des composants!")
        return keys
    
    except Exception as e:
        print(f"Erreur lors de la création des clés: {e}")
        return None

def display_key_components(keys):
    """Affiche les composants des clés RSA"""
    e, n = keys["public"]
    d, _ = keys["private"]
    
    print("\n=== Composants des clés RSA ===")
    print(f"Module (n): {n}")
    print(f"Exposant public (e): {e}")
    print(f"Exposant privé (d): {d}")
    
    # Vérifier que e et d sont inverses l'un de l'autre modulo phi(n)
    # C'est impossible sans connaître phi(n), donc on fait un test simple
    test_value = 42
    encrypted = pow(test_value, e, n)
    decrypted = pow(encrypted, d, n)
    print(f"Test de clés (42 -> e -> d -> 42): {'Réussi' if decrypted == test_value else 'Échec'}")

def serialize_signature(signature):
    """Convertit une signature en chaîne base64"""
    signature_bytes = signature.to_bytes((signature.bit_length() + 7) // 8, byteorder='big')
    return base64.b64encode(signature_bytes).decode('utf-8')

def deserialize_signature(signature_str):
    """Convertit une chaîne base64 en signature"""
    try:
        signature_bytes = base64.b64decode(signature_str)
        return int.from_bytes(signature_bytes, byteorder='big')
    except:
        raise ValueError("Format de signature invalide")

def main():
    """Fonction principale du programme"""
    print("=" * 80)
    print("SYSTÈME DE SIGNATURE NUMÉRIQUE RSA ")
    print("=" * 80)
    
    # Variable pour stocker les clés
    keys = None
    
    # Demander à l'utilisateur comment il souhaite obtenir les clés
    key_choice = input("\nComment souhaitez-vous obtenir les clés RSA?\n"
                      "1. Générer de nouvelles clés\n"
                      "2. Charger des clés depuis des fichiers\n"
                      "3. Entrer les composants manuellement (e, d, n)\n"
                      "Votre choix (1/2/3): ")
    
    if key_choice == "3":
        # Entrée manuelle des composants
        print("\nVeuillez entrer les composants des clés RSA:")
        try:
            n = int(input("Module (n): "))
            
            e_input = input("Exposant public (e) (optionnel, appuyez sur Entrée pour passer): ")
            d_input = input("Exposant privé (d) (optionnel, appuyez sur Entrée pour passer): ")
            
            e = int(e_input) if e_input else None
            d = int(d_input) if d_input else None
            
            keys = create_keys_from_components(e, d, n)
            
            if keys is None:
                print("Impossible de continuer sans clés valides. Le programme va s'arrêter.")
                return
        except ValueError as e:
            print(f"Erreur de conversion: {e}")
            return
    
    elif key_choice == "2":
        # Utiliser des clés existantes
        private_key_file = input("Chemin vers le fichier de clé privée (par défaut: rsa_signature_private.json): ") or "rsa_signature_private.json"
        public_key_file = input("Chemin vers le fichier de clé publique (par défaut: rsa_signature_public.json): ") or "rsa_signature_public.json"
        
        keys = load_keys_from_files(private_key_file, public_key_file)
        
        if keys is None:
            print("Impossible de continuer sans clés valides. Le programme va s'arrêter.")
            return
    else:
        # Génération des clés RSA (option par défaut)
        bits = int(input("Taille des clés en bits (par défaut: 1024): ") or "1024")
        
        keys = generate_keypair(bits)
        
        # Option pour sauvegarder les clés
        save_keys_option = input("Voulez-vous sauvegarder les clés? (o/n): ").lower()
        if save_keys_option == 'o' or save_keys_option == 'oui':
            private_key_file = input("Nom du fichier pour la clé privée (par défaut: rsa_signature_private.json): ") or "rsa_signature_private.json"
            public_key_file = input("Nom du fichier pour la clé publique (par défaut: rsa_signature_public.json): ") or "rsa_signature_public.json"
            save_keys(keys, private_key_file, public_key_file)
    
    # Afficher les composants des clés RSA
    display_choice = input("Voulez-vous afficher les composants des clés (e, d, n)? (o/n): ").lower()
    if display_choice == 'o' or display_choice == 'oui':
        display_key_components(keys)
    
    # Menu principal pour les opérations
    while True:
        print("\n=== Menu principal ===")
        print("1. Signer un message")
        print("2. Vérifier une signature")
        print("3. Générer de nouvelles clés")
        print("4. Afficher les clés actuelles")
        print("5. Introduire de nouvelles clés manuellement")
        print("6. Quitter")
        
        choice = input("\nVotre choix (1-6): ").strip()
        
        if choice == "1":
            # Signature
            message = input("\nEntrez le message à signer: ")
            if not message:
                print("Message vide, opération annulée.")
                continue
            
            try:
                signature = sign(message, keys["private"])
                signature_base64 = serialize_signature(signature)
                print(f"\nSignature (Base64): {signature_base64}")
                print(f"Signature (entier): {signature}")
            except Exception as e:
                print(f"\n❌ Erreur lors de la signature: {e}")
            
        elif choice == "2":
            # Vérification
            message = input("\nEntrez le message à vérifier: ")
            if not message:
                print("Message vide, opération annulée.")
                continue
            
            signature_input = input("\nEntrez la signature (Base64 ou entier): ")
            if not signature_input:
                print("Signature vide, opération annulée.")
                continue
            
            try:
                # Essayer de traiter comme Base64 d'abord, puis comme entier
                try:
                    signature = deserialize_signature(signature_input)
                except:
                    signature = int(signature_input)
                
                if verify(message, signature, keys["public"]):
                    print("\n✅ Vérification réussie: La signature est valide!")
                else:
                    print("\n❌ Échec de la vérification: La signature est invalide!")
            except Exception as e:
                print(f"\n❌ Erreur lors de la vérification: {e}")
                
        elif choice == "3":
            # Régénération des clés
            bits = int(input("Taille des clés en bits (par défaut: 1024): ") or "1024")
            
            keys = generate_keypair(bits)
            
            # Option pour sauvegarder les clés
            save_keys_option = input("Voulez-vous sauvegarder les clés? (o/n): ").lower()
            if save_keys_option == 'o' or save_keys_option == 'oui':
                private_key_file = input("Nom du fichier pour la clé privée (par défaut: rsa_signature_private.json): ") or "rsa_signature_private.json"
                public_key_file = input("Nom du fichier pour la clé publique (par défaut: rsa_signature_public.json): ") or "rsa_signature_public.json"
                save_keys(keys, private_key_file, public_key_file)
            
            display_key_components(keys)
            
        elif choice == "4":
            # Afficher les clés
            if keys:
                display_key_components(keys)
            else:
                print("Aucune clé disponible.")
        
        elif choice == "5":
            # Introduire de nouvelles clés manuellement
            print("\nVeuillez entrer les composants des clés RSA:")
            try:
                n = int(input("Module (n): "))
                
                e_input = input("Exposant public (e) (optionnel, appuyez sur Entrée pour passer): ")
                d_input = input("Exposant privé (d) (optionnel, appuyez sur Entrée pour passer): ")
                
                e = int(e_input) if e_input else None
                d = int(d_input) if d_input else None
                
                new_keys = create_keys_from_components(e, d, n)
                
                if new_keys:
                    keys = new_keys
                    print("Nouvelles clés intégrées avec succès!")
                    display_key_components(keys)
            except ValueError as e:
                print(f"Erreur de conversion: {e}")
            
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