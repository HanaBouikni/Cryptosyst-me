import base64
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def derive_key(passphrase, salt=b'static_salt', iterations=1000):
    """Dérive une clé AES à partir d'un mot de passe en utilisant PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # Clé de 256 bits
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(passphrase.encode('utf-8'))


def aes_encrypt(plaintext, passphrase):
    """Chiffre le texte clair à l'aide d'AES-GCM."""
    # Dérivation de la clé
    key = derive_key(passphrase)
    
    # Utilisation d'un IV fixe pour la démonstration (ne pas faire en production!)
    iv = b'\x00' * 12  # 12 bytes (96 bits) pour GCM
    
    # Préparation du cipher
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv))
    encryptor = cipher.encryptor()
    
    # Chiffrement
    ciphertext = encryptor.update(plaintext.encode('utf-8')) + encryptor.finalize()
    
    # Retourne le tag d'authentification et le texte chiffré
    return encryptor.tag + ciphertext


def aes_decrypt(ciphertext_with_tag, passphrase):
    """Déchiffre le texte chiffré à l'aide d'AES-GCM."""
    # Dérivation de la clé
    key = derive_key(passphrase)
    
    # IV fixe (comme pour le chiffrement)
    iv = b'\x00' * 12  # 12 bytes
    
    # Le tag d'authentification est les 16 premiers octets
    tag, ciphertext = ciphertext_with_tag[:16], ciphertext_with_tag[16:]
    
    # Préparation du cipher
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag))
    decryptor = cipher.decryptor()
    
    # Déchiffrement
    try:
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return plaintext.decode('utf-8')
    except Exception as e:
        raise ValueError(f"Erreur de déchiffrement: {e}")


def main():
    """Interface CLI simple pour tester le chiffrement/déchiffrement AES."""
    print("=" * 50)
    print("        CHIFFREMENT / DÉCHIFFREMENT AES")
    print("=" * 50)
    
    while True:
        print("\nQue voulez-vous faire?")
        print("1. Chiffrer un texte")
        print("2. Déchiffrer un texte")
        print("3. Quitter")
        
        choice = input("\nVotre choix (1-3): ")
        
        if choice == '1':
            plaintext = input("Entrez le texte à chiffrer: ")
            passphrase = input("Entrez la clé de chiffrement: ")
            
            try:
                encrypted = aes_encrypt(plaintext, passphrase)
                encrypted_b64 = base64.b64encode(encrypted).decode('utf-8')
                
                print("\nTexte chiffré (Base64):")
                print(encrypted_b64)
            except Exception as e:
                print(f"\nErreur lors du chiffrement: {e}")
                
        elif choice == '2':
            encrypted_b64 = input("Entrez le texte chiffré (Base64): ")
            passphrase = input("Entrez la clé de déchiffrement: ")
            
            try:
                encrypted = base64.b64decode(encrypted_b64)
                decrypted = aes_decrypt(encrypted, passphrase)
                
                print("\nTexte déchiffré:")
                print(decrypted)
            except Exception as e:
                print(f"\nErreur lors du déchiffrement: {e}")
                
        elif choice == '3':
            print("\nAu revoir!")
            break
            
        else:
            print("\nChoix invalide. Veuillez réessayer.")


if __name__ == "__main__":
    main()