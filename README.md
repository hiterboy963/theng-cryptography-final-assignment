# Project Topic Title: Secure Digital Document Signer and Verifier

### Short Description of my project

My project is to build a secure document-signing tool that ensures document integrity and authenticity using the Asymmetric Cryptography algorithm (RSA), symmetric cryptography algorithm (AES), and the Hashing algorithm (SHA-256). This tool works by letting users generate their RSA public/private key pairs with the private key encrypted using AES with a password, then sign their document with the generated private key to generate the document signature. When users want to verify the document, they will use the signer's public key on the document signature to detect if the file has been tampered with or corrupted.

### Installation & Setup Instructions

System Requirements:
- Python version 3.8 or higher
- pip (Python Package Installer) installed

+ Step 1: Clone my repository
Open your terminal and run:
```bash
git clone [https://github.com/hiterboy963/theng-cryptography-final-assignment]
cd theng-cryptography-final-assignment
```

+ step 2: Install Dependencies
Open your terminal and run:
```bash
pip install cryptography
```

### Usage Example

This application runs in the terminal, so open your terminal and run the main script:
```bash
python code.py
```
### Dependencies/Libraries Used

+ cryptography (the main library) consists of:
- rsa: generate key pair
- padding: add PSS (Probabilistic Signature Scheme) signing standard for more security
- hashes: for SHA-256 to work
- serialization: for saving key pairs into a .pem file format
- invaildsignature: for error message
+ getpass: Python dependency for masking passwords when typing
+ os: used for file system handling

