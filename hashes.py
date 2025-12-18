import hashlib
import bcrypt
from argon2 import PasswordHasher
import os
import base64

def hash_md5(password: str) -> str:
    return hashlib.md5(password.encode()).hexdigest()

def hash_sha1(password: str) -> str:
    return hashlib.sha1(password.encode()).hexdigest()

def hash_sha256(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

def hash_sha512(password: str) -> str:
    return hashlib.sha512(password.encode()).hexdigest()

def hash_pbkdf2(password: str, salt: bytes) -> str:
    dk = hashlib.pbkdf2_hmac(
        hash_name="sha256",
        password=password.encode(),
        salt=salt,
        iterations=100_000
    )
    return base64.b64encode(dk).decode()

def hash_bcrypt(password: str) -> str:
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode(), salt).decode()

def hash_argon2(password: str) -> str:
    ph = PasswordHasher()
    return ph.hash(password)

def main():
    print("\n=== Multi-Algorithm Password Hasher ===\n")
    password = input("Enter your password: ")

    print("\n--- Hash Outputs ---\n")

    print(f"MD5:      {hash_md5(password)}")
    print(f"SHA1:     {hash_sha1(password)}")
    print(f"SHA256:   {hash_sha256(password)}")
    print(f"SHA512:   {hash_sha512(password)}")

    salt = os.urandom(16)
    print(f"PBKDF2:   {hash_pbkdf2(password, salt)}")

    print(f"bcrypt:   {hash_bcrypt(password)}")
    print(f"Argon2:   {hash_argon2(password)}")

    print("\nNote:")
    print("- MD5/SHA1 are cryptographically broken")
    print("- bcrypt, PBKDF2, and Argon2 are designed for password storage\n")

if __name__ == "__main__":
    main()
