import hashlib
import bcrypt
from argon2 import PasswordHasher
import yaml
from pathlib import Path


ph = PasswordHasher()




def load_config(path="config.yaml"):
with open(path, "r") as f:
return yaml.safe_load(f)




def hash_md5(password: str) -> str:
return hashlib.md5(password.encode()).hexdigest()




def hash_sha256(password: str) -> str:
return hashlib.sha256(password.encode()).hexdigest()




def hash_bcrypt(password: str, salt: bytes) -> str:
return bcrypt.hashpw(password.encode(), salt).decode()




def hash_argon2(password: str) -> str:
return ph.hash(password)




def main():
config = load_config()
input_file = Path(config["input_passwords"])
output_dir = Path(config["output_dir"])
output_dir.mkdir(parents=True, exist_ok=True)


passwords = input_file.read_text().splitlines()


if "md5" in config["algorithms"]:
with open(output_dir / "md5.txt", "w") as f:
for pw in passwords:
f.write(hash_md5(pw) + "
")


if "sha256" in config["algorithms"]:
with open(output_dir / "sha256.txt", "w") as f:
for pw in passwords:
f.write(hash_sha256(pw) + "
")


if "bcrypt" in config["algorithms"]:
with open(output_dir / "bcrypt.txt", "w") as f:
for pw in passwords:
salt = bcrypt.gensalt()
f.write(hash_bcrypt(pw, salt) + "
")


if "argon2" in config["algorithms"]:
with open(output_dir / "argon2.txt", "w") as f:
for pw in passwords:
f.write(hash_argon2(pw) + "
")




if __name__ == "__main__":
main()
