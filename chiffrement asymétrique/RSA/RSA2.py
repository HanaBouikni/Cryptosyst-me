def load_keys_from_files(private_key_file="private_key.pem", public_key_file="public_key.pem"):
    """
    Charge les clés RSA à partir de fichiers PEM.
    
    Args:
        private_key_file (str): Chemin vers le fichier de clé privée
        public_key_file (str): Chemin vers le fichier de clé publique
        
    Returns:
        tuple: (clé_privée, clé_publique) ou (None, None) en cas d'erreur
    """
    try:
        # Chargement de la clé privée
        with open(private_key_file, "rb") as private_file:
            private_key = serialization.load_pem_private_key(
                private_file.read(),
                password=None  # Pas de mot de passe pour cet exemple
            )
        
        # Chargement de la clé publique
        with open(public_key_file, "rb") as public_file:
            public_key = serialization.load_pem_public_key(
                public_file.read()
            )
        
        print(f"Clés chargées avec succès depuis '{private_key_file}' et '{public_key_file}'")
        return private_key, public_key
    
    except Exception as e:
        print(f"Erreur lors du chargement des clés: {e}")
        return None, None#!/usr/bin/env python3
"""
rsa_crypto.py - Implémentation d'un cryptosystème RSA

Ce script génère une paire de clés RSA, chiffre un message fourni par l'utilisateur
avec la clé publique, puis le déchiffre avec la clé privée. Il utilise le padding
OAEP avec SHA-256 pour un chiffrement sécurisé.

Prérequis: pip install cryptography sympy
"""

import base64
import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization


def generate_key_pair(key_size=2048):
    """
    Génère une paire de clés RSA de la taille spécifiée.
    
    Args:
        key_size (int): Taille de la clé en bits (défaut: 2048)
        
    Returns:
        tuple: (clé_privée, clé_publique)
    """
    print(f"Génération d'une paire de clés RSA de {key_size} bits...")
    
    # Génération de la clé privée RSA
    private_key = rsa.generate_private_key(
        public_exponent=65537,  # Exposant public standard (nombre premier de Fermat)
        key_size=key_size
    )
    
    # Extraction de la clé publique à partir de la clé privée
    public_key = private_key.public_key()
    
    print("Paire de clés générée avec succès!")
    return private_key, public_key


def encrypt_message(message, public_key):
    """
    Chiffre un message avec la clé publique RSA.
    
    Args:
        message (str): Message en clair à chiffrer
        public_key: Clé publique RSA
        
    Returns:
        bytes: Message chiffré
    """
    print("Chiffrement du message avec la clé publique...")
    
    # Conversion du message (chaîne de caractères) en bytes
    message_bytes = message.encode('utf-8')
    
    # Chiffrement avec un padding OAEP et SHA-256 (bonne pratique de sécurité)
    encrypted_message = public_key.encrypt(
        message_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    return encrypted_message


def decrypt_message(encrypted_message, private_key):
    """
    Déchiffre un message avec la clé privée RSA.
    
    Args:
        encrypted_message (bytes): Message chiffré
        private_key: Clé privée RSA
        
    Returns:
        str: Message déchiffré
    """
    print("Déchiffrement du message avec la clé privée...")
    
    # Déchiffrement avec le même padding utilisé pour le chiffrement
    decrypted_message_bytes = private_key.decrypt(
        encrypted_message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    # Conversion des bytes en chaîne de caractères
    decrypted_message = decrypted_message_bytes.decode('utf-8')
    
    return decrypted_message


def encode_to_base64(data):
    """
    Encode des données binaires en chaîne base64.
    
    Args:
        data (bytes): Données à encoder
        
    Returns:
        str: Chaîne encodée en base64
    """
    return base64.b64encode(data).decode('utf-8')


def save_keys(private_key, public_key, private_key_file="private_key.pem", public_key_file="public_key.pem"):
    """
    Enregistre les clés dans des fichiers PEM.
    
    Args:
        private_key: Clé privée RSA
        public_key: Clé publique RSA
        private_key_file (str): Nom du fichier pour la clé privée
        public_key_file (str): Nom du fichier pour la clé publique
    """
    # Sérialisation de la clé privée en format PEM
    pem_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    # Sérialisation de la clé publique en format PEM
    pem_public = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    # Enregistrement des clés dans des fichiers
    with open(private_key_file, "wb") as private_file:
        private_file.write(pem_private)
    
    with open(public_key_file, "wb") as public_file:
        public_file.write(pem_public)
    
    print(f"Clés enregistrées dans '{private_key_file}' et '{public_key_file}'")


def display_key_components(private_key, public_key):
    """
    Affiche les composants mathématiques des clés RSA (n, e, d).
    
    Args:
        private_key: Clé privée RSA
        public_key: Clé publique RSA
    """
    # Extraction des nombres n et e de la clé publique
    public_numbers = public_key.public_numbers()
    n = public_numbers.n  # Modulus
    e = public_numbers.e  # Exposant public
    
    # Extraction du nombre d de la clé privée
    private_numbers = private_key.private_numbers()
    d = private_numbers.d  # Exposant privé
    
    print("\n=== Composants des clés RSA ===")
    print(f"Modulus (n): {n}")
    print(f"Exposant public (e): {e}")
    print(f"Exposant privé (d): {d}")
    
    # On peut aussi afficher p et q, les facteurs premiers de n
    p = private_numbers.p
    q = private_numbers.q
    print(f"Facteur premier p: {p}")
    print(f"Facteur premier q: {q}")
    print(f"Vérification: p * q = n? {p * q == n}")


def create_keys_from_components(e, d, n, p=None, q=None):
    """
    Crée une paire de clés RSA à partir des composants mathématiques.
    
    Args:
        e (int): Exposant public
        d (int): Exposant privé
        n (int): Modulus
        p (int, optional): Premier facteur premier de n
        q (int, optional): Second facteur premier de n
    
    Returns:
        tuple: (clé_privée, clé_publique) ou (None, None) en cas d'erreur
    """
    try:
        # Si p et q ne sont pas fournis, nous ne pouvons pas créer une clé privée complète
        if p is None or q is None:
            # Nous pouvons créer un "faux" p et q pour la structure
            # Cela ne fonctionnera que pour des opérations de base et n'est pas recommandé en production
            import sympy
            if p is None and q is None:
                # Essayer de factoriser n (peut être très lent pour de grandes valeurs de n)
                print("Tentative de factorisation de n pour trouver p et q...")
                factors = list(sympy.factorint(n).keys())
                if len(factors) >= 2:
                    p, q = factors[0], factors[1]
                else:
                    raise ValueError("Impossible de factoriser n correctement")
            elif p is None:
                p = n // q
            else:
                q = n // p
            
            # Vérification
            if p * q != n:
                raise ValueError("Les valeurs p et q ne sont pas valides (p*q != n)")

        # Calcul des valeurs dérivées nécessaires pour créer une clé privée RSA
        dmp1 = d % (p - 1)
        dmq1 = d % (q - 1)
        iqmp = pow(q, -1, p)  # q^(-1) mod p
        
        # Création des objets de nombres pour les clés
        from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers, RSAPrivateNumbers
        
        public_numbers = RSAPublicNumbers(e=e, n=n)
        private_numbers = RSAPrivateNumbers(
            p=p,
            q=q,
            d=d,
            dmp1=dmp1,
            dmq1=dmq1,
            iqmp=iqmp,
            public_numbers=public_numbers
        )
        
        # Création des objets de clés
        from cryptography.hazmat.backends import default_backend
        private_key = private_numbers.private_key(default_backend())
        public_key = public_numbers.public_key(default_backend())
        
        print("Clés créées avec succès à partir des composants!")
        return private_key, public_key
    
    except Exception as e:
        print(f"Erreur lors de la création des clés à partir des composants: {e}")
        return None, None


def main():
    """Fonction principale du programme"""
    print("=== Cryptosystème RSA ===\n")
    
    # Demander à l'utilisateur comment il souhaite obtenir les clés
    key_choice = input("Comment souhaitez-vous obtenir les clés RSA?\n"
                      "1. Générer de nouvelles clés\n"
                      "2. Charger des clés depuis des fichiers\n"
                      "3. Entrer les composants manuellement (e, d, n)\n"
                      "Votre choix (1/2/3): ")
    
    if key_choice == "3":
        # Entrée manuelle des composants
        print("\nVeuillez entrer les composants des clés RSA:")
        try:
            # Conversion en entiers pour les grands nombres
            n = int(input("Modulus (n): "))
            e = int(input("Exposant public (e): "))
            d = int(input("Exposant privé (d): "))
            
            p_input = input("Facteur premier p (optionnel, appuyez sur Entrée pour passer): ")
            q_input = input("Facteur premier q (optionnel, appuyez sur Entrée pour passer): ")
            
            p = int(p_input) if p_input else None
            q = int(q_input) if q_input else None
            
            private_key, public_key = create_keys_from_components(e, d, n, p, q)
            
            if private_key is None or public_key is None:
                print("Impossible de continuer sans clés valides. Le programme va s'arrêter.")
                return
        except ValueError as e:
            print(f"Erreur de conversion: {e}")
            return
    
    elif key_choice == "2":
        # Utiliser des clés existantes
        private_key_file = input("Chemin vers le fichier de clé privée (par défaut: private_key.pem): ") or "private_key.pem"
        public_key_file = input("Chemin vers le fichier de clé publique (par défaut: public_key.pem): ") or "public_key.pem"
        
        private_key, public_key = load_keys_from_files(private_key_file, public_key_file)
        
        if private_key is None or public_key is None:
            print("Impossible de continuer sans clés valides. Le programme va s'arrêter.")
            return
    else:
        # Génération des clés RSA (option par défaut)
        private_key, public_key = generate_key_pair()
        
        # Option pour sauvegarder les clés
        save_keys_option = input("Voulez-vous sauvegarder les clés? (o/n): ").lower()
        if save_keys_option == 'o' or save_keys_option == 'oui':
            save_keys(private_key, public_key)
    
    # Afficher les composants des clés RSA
    display_choice = input("Voulez-vous afficher les composants des clés (e, d, n, p, q)? (o/n): ").lower()
    if display_choice == 'o' or display_choice == 'oui':
        display_key_components(private_key, public_key)
    
    # Demande à l'utilisateur de saisir un message
    original_message = input("\nEntrez le message à chiffrer: ")
    
    # Vérification que le message n'est pas vide
    if not original_message:
        print("Erreur: Le message est vide!")
        return
    
    # Chiffrement du message
    encrypted_message = encrypt_message(original_message, public_key)
    
    # Encodage du message chiffré en base64 pour l'affichage
    encrypted_base64 = encode_to_base64(encrypted_message)
    
    # Déchiffrement du message
    decrypted_message = decrypt_message(encrypted_message, private_key)
    
    # Affichage des résultats
    print("\n=== Résultats ===")
    print(f"Message original: {original_message}")
    print(f"Message chiffré (Base64): {encrypted_base64}")
    print(f"Message déchiffré: {decrypted_message}")
    
    # Vérification de l'intégrité
    if original_message == decrypted_message:
        print("\n✓ Vérification réussie: Le message déchiffré correspond au message original.")
    else:
        print("\n✗ Erreur: Le message déchiffré ne correspond pas au message original!")


if __name__ == "__main__":
    main()