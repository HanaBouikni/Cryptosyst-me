
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def chacha20_encrypt(plaintext, key):
    """Chiffre le texte clair à l'aide de ChaCha20."""
    # Préparation de la clé (ChaCha20 nécessite une clé de 32 octets)
    key_bytes = key.encode('utf-8')
    if len(key_bytes) < 32:
        # Padding de la clé si elle est trop courte
        key_bytes = key_bytes.ljust(32, b'\0')
    elif len(key_bytes) > 32:
        # Tronquer la clé si elle est trop longue
        key_bytes = key_bytes[:32]
    
    # ChaCha20 nécessite un nonce de 16 octets (128 bits)
    # Pour la simplicité, nous utilisons un nonce fixe rempli de zéros
    # Ne jamais faire cela en production!
    nonce = b'\x00' * 16
    
    # Préparation de l'algorithme de chiffrement
    algorithm = algorithms.ChaCha20(key_bytes, nonce)
    cipher = Cipher(algorithm, mode=None)
    encryptor = cipher.encryptor()
    
    # Chiffrement du texte
    ciphertext = encryptor.update(plaintext.encode('utf-8')) + encryptor.finalize()
    
    return ciphertext


def chacha20_decrypt(ciphertext, key):
    """Déchiffre le texte chiffré à l'aide de ChaCha20."""
    # Préparation de la clé
    key_bytes = key.encode('utf-8')
    if len(key_bytes) < 32:
        key_bytes = key_bytes.ljust(32, b'\0')
    elif len(key_bytes) > 32:
        key_bytes = key_bytes[:32]
    
    # Même nonce que pour le chiffrement
    nonce = b'\x00' * 16
    
    # Préparation du déchiffrement
    algorithm = algorithms.ChaCha20(key_bytes, nonce)
    cipher = Cipher(algorithm, mode=None)
    decryptor = cipher.decryptor()
    
    # Déchiffrement
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    
    return plaintext.decode('utf-8')


def main():
    """Interface CLI simple pour tester le chiffrement/déchiffrement ChaCha20."""
    print("=" * 50)
    print("     CHIFFREMENT / DÉCHIFFREMENT ChaCha20")
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
                encrypted = chacha20_encrypt(plaintext, key)
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
                decrypted = chacha20_decrypt(encrypted, key)
                
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