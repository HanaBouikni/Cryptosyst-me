
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding


def blowfish_encrypt(plaintext, key):
    """Chiffre le texte clair à l'aide de Blowfish."""
    # Préparation de la clé (1-56 octets pour Blowfish)
    key_bytes = key.encode('utf-8')
    
    # Padding du texte à chiffrer
    padder = padding.PKCS7(64).padder()  # 64 bits pour Blowfish
    padded_data = padder.update(plaintext.encode('utf-8')) + padder.finalize()
    
    # Utiliser un IV (vecteur d'initialisation) de 8 octets remplis de zéros pour la démo
    iv = b'\x00' * 8
    
    # Chiffrement Blowfish en mode CBC
    cipher = Cipher(algorithms.Blowfish(key_bytes), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    
    return ciphertext


def blowfish_decrypt(ciphertext, key):
    """Déchiffre le texte chiffré à l'aide de Blowfish."""
    # Préparation de la clé
    key_bytes = key.encode('utf-8')
    
    # IV fixe
    iv = b'\x00' * 8
    
    # Déchiffrement
    cipher = Cipher(algorithms.Blowfish(key_bytes), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    
    # Enlever le padding
    unpadder = padding.PKCS7(64).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    
    return plaintext.decode('utf-8')


def main():
    """Interface CLI simple pour tester le chiffrement/déchiffrement Blowfish."""
    print("=" * 50)
    print("      CHIFFREMENT / DÉCHIFFREMENT BLOWFISH")
    print("=" * 50)
    
    while True:
        print("\nQue voulez-vous faire?")
        print("1. Chiffrer un texte")
        print("2. Déchiffrer un texte")
        print("3. Quitter")
        
        choice = input("\nVotre choix (1-3): ")
        
        if choice == '1':
            plaintext = input("Entrez le texte à chiffrer: ")
            key = input("Entrez la clé de chiffrement: ")
            
            try:
                encrypted = blowfish_encrypt(plaintext, key)
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
                decrypted = blowfish_decrypt(encrypted, key)
                
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