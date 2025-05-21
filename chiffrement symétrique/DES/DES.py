import base64
import warnings
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

# Ignorer l'avertissement de dépréciation pour TripleDES
warnings.filterwarnings("ignore", category=DeprecationWarning, module="cryptography")


def des_encrypt(plaintext, key):
    """Chiffre le texte clair à l'aide de DES."""
    # Nous devons padder la clé si nécessaire (DES utilise des clés de 8 octets)
    key_bytes = key.encode('utf-8')
    if len(key_bytes) < 8:
        # Padding de la clé
        key_bytes = key_bytes.ljust(8, b'\0')
    elif len(key_bytes) > 8:
        # Tronquer la clé
        key_bytes = key_bytes[:8]
    
    # Padding du texte à chiffrer
    padder = padding.PKCS7(64).padder()  # 64 bits pour DES
    padded_data = padder.update(plaintext.encode('utf-8')) + padder.finalize()
    
    # Utiliser un IV (vecteur d'initialisation) de 8 octets remplis de zéros pour la démo
    iv = b'\x00' * 8
    
    # Chiffrement DES en mode CBC
    cipher = Cipher(algorithms.TripleDES(key_bytes), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    
    return ciphertext


def des_decrypt(ciphertext, key):
    """Déchiffre le texte chiffré à l'aide de DES."""
    # Préparation de la clé
    key_bytes = key.encode('utf-8')
    if len(key_bytes) < 8:
        key_bytes = key_bytes.ljust(8, b'\0')
    elif len(key_bytes) > 8:
        key_bytes = key_bytes[:8]
    
    # IV fixe
    iv = b'\x00' * 8
    
    # Déchiffrement
    cipher = Cipher(algorithms.TripleDES(key_bytes), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    
    # Enlever le padding
    unpadder = padding.PKCS7(64).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    
    return plaintext.decode('utf-8')


def main():
    """Interface CLI simple pour tester le chiffrement/déchiffrement DES."""
    print("=" * 50)
    print("        CHIFFREMENT / DÉCHIFFREMENT DES")
    print("=" * 50)
    print("Note: DES est considéré comme obsolète en matière de sécurité.")
    
    while True:
        print("\nQue voulez-vous faire?")
        print("1. Chiffrer un texte")
        print("2. Déchiffrer un texte")
        print("3. Quitter")
        
        choice = input("\nVotre choix (1-3): ")
        
        if choice == '1':
            plaintext = input("Entrez le texte à chiffrer: ")
            key = input("Entrez la clé de chiffrement (8 caractères max): ")
            
            try:
                encrypted = des_encrypt(plaintext, key)
                encrypted_b64 = base64.b64encode(encrypted).decode('utf-8')
                
                print("\nTexte chiffré (Base64):")
                print(encrypted_b64)
            except Exception as e:
                print(f"\nErreur lors du chiffrement: {e}")
                
        elif choice == '2':
            encrypted_b64 = input("Entrez le texte chiffré (Base64): ")
            key = input("Entrez la clé de déchiffrement: ")
            
            try:
                encrypted = base64.b64decode(encrypted_b64)
                decrypted = des_decrypt(encrypted, key)
                
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