import hashlib
import bcrypt
from argon2 import PasswordHasher
import os
import base64
from cryptography.fernet import Fernet

INTERNAL_KEY = b'9KpZ5n2W4mXvJ7eYxwJc6tH9QzFZ9QeH0r5AqkXzH1M='
fernet = Fernet(INTERNAL_KEY)

ph = PasswordHasher()

def hash_md5(p): return hashlib.md5(p.encode()).hexdigest()
def hash_sha1(p): return hashlib.sha1(p.encode()).hexdigest()
def hash_sha256(p): return hashlib.sha256(p.encode()).hexdigest()
def hash_sha512(p): return hashlib.sha512(p.encode()).hexdigest()

def hash_pbkdf2(p):
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", p.encode(), salt, 100_000)
    return base64.b64encode(dk).decode()

def hash_bcrypt(p):
    return bcrypt.hashpw(p.encode(), bcrypt.gensalt()).decode()

def hash_argon2(p):
    return ph.hash(p)

# ======================
# Encryption
# ======================

def encrypt_text(t):
    return fernet.encrypt(t.encode()).decode()

def decrypt_text(t):
    return fernet.decrypt(t.encode()).decode()

# ======================
# Hash detection
# ======================

def detect_algorithm(v):
    if v.startswith("$2"):
        return "bcrypt"
    if v.startswith("$argon2"):
        return "Argon2"
    if len(v) == 32:
        return "MD5"
    if len(v) == 40:
        return "SHA1"
    if len(v) == 64:
        return "SHA256"
    if len(v) == 128:
        return "SHA512"
    return "AES (Fernet) or Unknown"

# ======================
# Main
# ======================

def main():
    print("\n=== Security Tool ===")
    print("1. Encrypt / Hash")
    print("2. Decrypt / Analyze")

    choice = input("\nChoose option: ").strip()

    if choice == "1":
        print("\nChoose Algorithm:")
        print("1. AES (Encryptable)")
        print("2. MD5")
        print("3. SHA1")
        print("4. SHA256")
        print("5. SHA512")
        print("6. PBKDF2")
        print("7. bcrypt")
        print("8. Argon2")

        algo = input("\nAlgorithm choice: ").strip()
        text = input("Enter input text: ")

        match algo:
            case "1":
                result = encrypt_text(text)
                algo_name = "AES (Fernet)"
            case "2":
                result = hash_md5(text)
                algo_name = "MD5"
            case "3":
                result = hash_sha1(text)
                algo_name = "SHA1"
            case "4":
                result = hash_sha256(text)
                algo_name = "SHA256"
            case "5":
                result = hash_sha512(text)
                algo_name = "SHA512"
            case "6":
                result = hash_pbkdf2(text)
                algo_name = "PBKDF2"
            case "7":
                result = hash_bcrypt(text)
                algo_name = "bcrypt"
            case "8":
                result = hash_argon2(text)
                algo_name = "Argon2"
            case _:
                print("Invalid algorithm.")
                return

        print("\n--- Output ---")
        print(result)
        print(f"Algorithm used: {algo_name}")

    elif choice == "2":
        value = input("\nEnter encrypted value or hash: ")

        try:
            decrypted = decrypt_text(value)
            print("\n--- Decryption Successful ---")
            print(f"Decrypted text: {decrypted}")
            print("Algorithm used: AES (Fernet)")
        except Exception:
            algo = detect_algorithm(value)
            print("\n--- Cannot Decrypt ---")
            print("This value is a hash.")
            print(f"Detected algorithm: {algo}")

    else:
        print("Invalid option.")

if __name__ == "__main__":
    main()
