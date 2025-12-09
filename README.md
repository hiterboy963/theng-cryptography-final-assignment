# Project Topic Title: Secure Digital Document Signer

### Short Description of my project

My project is to build a secure document-signing tool that ensures document integrity and authenticity using the Asymmetric Cryptography algorithm (RSA) and the Hashing algorithm (SHA-256). This tool works by letting users generate their RSA public/private key pairs, then sign their document with the generated private key, and when users want to verify the document, they will use the document's public key to detect if the file has been tampered with or corrupted.

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

- cryptography: used for RSA key generation
- hashlib: used for calculating SHA-256 file hashes
- os: used for file system handling

