# Cryptosyst-me
Ce projet regroupe une implémentation en Python de plusieurs algorithmes classiques et modernes de cryptographie. Il est structuré en différents modules couvrant la cryptographie classique, symétrique, asymétrique, les fonctions de hachage et les signatures numériques. 

## 📦 Contenu détaillé

### 🔤 Cryptographie classique (`crypto_classique/`)
- **César, Affine, Vigenère, Playfair, Hill** : Chiffrements historiques simples à clés statiques.
- **One-Time Pad (OTP)** : Méthode de chiffrement théoriquement inviolable avec une clé unique.
- **Analyses** :
  - Analyse de fréquence
  - Indice de coïncidence
  - Test de Kasiski
  - Analyse automatique du Vigenère

### 🔐 Cryptographie symétrique (`crypto_symetrique/`)
- **AES** (Advanced Encryption Standard)
- **DES** (Data Encryption Standard)
- **RC4** : Algorithme de chiffrement par flot

### 🔓 Cryptographie asymétrique (`crypto_asymetrique/`)
- **RSA** : Chiffrement basé sur les grands nombres premiers
- **ElGamal** : Basé sur le logarithme discret

### 🧮 Fonctions de hachage (`hachage/`)
- **MD5**, **SHA** : Algorithmes de hachage cryptographique

### ✍️ Signature numérique (`signature_numerique/`)
- Signatures numériques avec **RSA** et **ElGamal**

## ⚙️ Pré-requis

- Python 3.x
- Aucun module externe requis pour la plupart des fichiers
- (Facultatif) `numpy` pour certaines implémentations matricielles (ex: Hill)

## 🚀 Exécution

Chaque fichier peut être exécuté séparément. Exemple :

```bash
python crypto_classique/cesar.py

