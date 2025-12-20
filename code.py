from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.exceptions import InvalidSignature
import os
import getpass

# 1. Function to generate RSA key pair
def generate_rsa_key_pair():
    print("\n GENERATING NEW RSA KEY PAIR")
    password = getpass.getpass("Enter a password to protect your private key: ")
    if not password:
        print("Password cannot be empty. Returning to main menu.")
        return
    print("Generating RSA key pair, please wait...")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()

    # save Private key and encrypt it with password
    with open("private_key.pem", "wb") as f:
        f.write(private_key.private_bytes( # convert key to bytes
            encoding=serialization.Encoding.PEM, # PEM format
            format=serialization.PrivateFormat.PKCS8, # PKCS8 format
            encryption_algorithm=serialization.BestAvailableEncryption(password.encode())
        ))

    # Save Public key
    with open("public_key.pem", "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    # finish generating message
    print("RSA key pair generated and saved as 'private_key.pem' and 'public_key.pem'.")

# 2. Signing Function
def sign_document():
    print("\n SIGN A DOCUMENT")
    filename = input("Enter the document filename to sign: ")
    if not filename:
        print("Document filename cannot be empty. Returning to main menu.")
        return
    if not os.path.exists(filename):
        print("Error: file does not exist. Returning to main menu.")
        return

    # Ask for password to decrypt private key
    password = getpass.getpass("Enter the password for your private key: ")
    if not password:
        print("Password cannot be empty. Returning to main menu.")
        return
    
    try: # load the encrypted private key
        with open("private_key.pem", "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=password.encode() # decryption with AES
            )

        # read the file contents
        with open(filename, "rb") as f:
            document_data = f.read()

        # sign the document contents using PSS padding and SHA256
        signature = private_key.sign(
            document_data, # data to sign
            padding.PSS( # padding scheme (salted)
                mgf=padding.MGF1(hashes.SHA256()), # mask generation function for PSS
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256() # hash algorithm
        )

        # Show signature in hex format
        print("Signature in (hex) format:", signature.hex())

        # save the signature to a new file
        sig_filename = filename + ".sig"
        with open(sig_filename, "wb") as f:
            f.write(signature)

        print(f"Document signed successfully. Signature saved as '{sig_filename}'.")

    except ValueError:
        print("Error: Incorrect password for private key. Returning to main menu.")
    except Exception as e:
        print(f"An error occurred: {e}")
    except FileNotFoundError:
        print("Error: Private key file not found. Returning to main menu.")

# 3. Verification Function
def verify_signature():
    print("\n VERIFY A DOCUMENT SIGNATURE")
    filename = input("Enter the document filename to verify: ")
    sig_filename = input("Enter the signature filename (end in .sig): ")
    if not os.path.exists(filename) or not os.path.exists(sig_filename):
        print("Error: One or both files do not exist. Returning to main menu.")
        return
    
    try:
        # load public key
        with open("public_key.pem", "rb") as key_file:
            public_key = serialization.load_pem_public_key(key_file.read())

        # read the file contents
        with open(filename, "rb") as f:
            document_data = f.read()
        
        # read the signature
        with open(sig_filename, "rb") as f:
            signature_data = f.read()
        
        print("Verifying signature, please wait...")

        # verify the signature
        public_key.verify(
            signature_data,
            document_data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        print("VAILD SIGNATURE: The document's signature is valid.")

    except InvalidSignature:
        print("INVALID SIGNATURE: The document's signature is NOT valid.")
    except Exception as e:
        print(f"An error occurred: {e}")

# Main Menu
def main():
    while True:
        print("\n SECURE DIGITAL DOCUMENT SIGNER AND VERIFIER")
        print("1. Generate RSA Key Pair")
        print("2. Sign a Document")
        print("3. Verify a Document Signature")
        print("4. Exit")
        choice = input("Please select an option (1-4): ")

        if choice == '1':
            generate_rsa_key_pair()
        elif choice == '2':
            sign_document()
        elif choice == '3':
            verify_signature()
        elif choice == '4':
            print("Exiting the program. Thank you!")
            break
        else:
            print("Invalid choice. Please select a valid option.")

# Run the main menu
if __name__ == "__main__":
    main()