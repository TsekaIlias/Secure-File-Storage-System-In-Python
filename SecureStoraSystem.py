import os, json, secrets, base64, hashlib
from pathlib import Path
from datetime import datetime
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
from typing import Optional, Tuple

USERS_DB = Path("users.json")
STORAGE_DIR = Path("secure_storage")
KEYS_DIR = Path("keys")
NONCE_DB = Path("nonces.json")
OTP_DB = Path("otp_store.json")


def initialize_system():
    STORAGE_DIR.mkdir(exist_ok=True)
    KEYS_DIR.mkdir(exist_ok=True)
    for f, default in [(USERS_DB, {}), (NONCE_DB, []), (OTP_DB, {})]:
        if not f.exists():
            f.write_text(json.dumps(default))


# ==========================================
# PART A - Hash & Salt
# ==========================================
def hash_password(password: str, salt: Optional[str] = None) -> Tuple[str, str]:
    if salt is None:
        salt = os.urandom(16).hex()

    salt_bytes = bytes.fromhex(salt)
    hash_bytes = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt_bytes, 100000
    )
    return hash_bytes.hex(), salt


def verify_password(password: str, stored_hash: str, salt: str) -> bool:
    calculated_hash, _ = hash_password(password, salt)
    return secrets.compare_digest(calculated_hash, stored_hash)


# ==========================================
# PART B - OTP & User Registration
# ==========================================
def admin_issue_otp(username: str) -> str:
    """Administrator: generates and stores OTP for a username"""
    otp = secrets.token_hex(4).upper()  # 8-character hex OTP
    store = json.loads(OTP_DB.read_text())
    store[username] = {
        "otp": otp,
        "issued_at": datetime.now().isoformat(),
        "used": False,
    }
    OTP_DB.write_text(json.dumps(store, indent=2))
    print(f"\n[ADMIN] New OTP issued for user {username}: {otp}")
    return otp



def register_user(username: str, otp_input: str, password: str) -> bool:
    otp_store = json.loads(OTP_DB.read_text())

    if username not in otp_store:
        print("Error: No OTP exists for this username.")
        return False

    if (
        otp_store[username]["used"] == True
        or otp_store[username]["otp"] != otp_input.upper()
    ):
        print("Error: The OTP is invalid or has already been used.")
        return False

    otp_store[username]["used"] = True
    OTP_DB.write_text(json.dumps(otp_store, indent=2))

    users_store = json.loads(USERS_DB.read_text())
    if username in users_store:
        print("Error: The username is already in use.")
        return False

    pwd_hash, pwd_salt = hash_password(password)
    users_store[username] = {
        "password_hash": pwd_hash,
        "salt": pwd_salt,
        "created_at": datetime.now().isoformat(),
    }
    USERS_DB.write_text(json.dumps(users_store, indent=2))

    generate_user_keys(username)
    print("Success: Registration completed successfully.")
    return True


# ==========================================
# PART C - Authentication
# ==========================================
def authenticate_user(username: str, password: str) -> bool:
    users_store = json.loads(USERS_DB.read_text())

    if username in users_store:
        stored_hash = users_store[username]["password_hash"]
        salt = users_store[username]["salt"]

        if verify_password(password, stored_hash, salt):
            return True

    print("\nIncorrect login credentials.")
    return False


# ==========================================
# PART D - RSA Keys
# ==========================================
def generate_user_keys(username: str):
    pk = rsa.generate_private_key(65537, 2048, default_backend())
    (KEYS_DIR / f"{username}_private.pem").write_bytes(
        pk.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    (KEYS_DIR / f"{username}_public.pem").write_bytes(
        pk.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )



def load_private_key(username: str):
    return serialization.load_pem_private_key(
        (KEYS_DIR / f"{username}_private.pem").read_bytes(),
        password=None,
        backend=default_backend(),
    )



def load_public_key(username: str):
    return serialization.load_pem_public_key(
        (KEYS_DIR / f"{username}_public.pem").read_bytes(), backend=default_backend()
    )


# ==========================================
# PART E - Nonce / Anti-Replay
# ==========================================
def generate_nonce() -> str:
    return secrets.token_hex(16)



def is_nonce_valid(nonce: str) -> bool:
    nonces = json.loads(NONCE_DB.read_text())

    if nonce in nonces:
        print("\n[WARNING] Replay Attack detected! The action was blocked.")
        return False

    nonces.append(nonce)
    NONCE_DB.write_text(json.dumps(nonces, indent=2))
    return True


# ==========================================
# PART F - Encryption & Digital Signature
# ==========================================
def encrypt_file(data: bytes) -> tuple:
    key = os.urandom(32)
    nonce_aes = os.urandom(12)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce_aes, data, None)
    return (ciphertext, key, nonce_aes)



def decrypt_file(ciphertext: bytes, key: bytes, nonce_aes: bytes) -> bytes:
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce_aes, ciphertext, None)



def sign_data(username: str, data: bytes, nonce: str) -> bytes:
    private_key = load_private_key(username)
    payload = data + nonce.encode()
    return private_key.sign(
        payload,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256(),
    )



def verify_signature(username: str, data: bytes, nonce: str, sig: bytes) -> bool:
    public_key = load_public_key(username)
    payload = data + nonce.encode()
    try:
        public_key.verify(
            sig,
            payload,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256(),
        )
        return True
    except InvalidSignature:
        return False


# ==========================================
# PART G - Upload, Download & CLI
# ==========================================
def upload_file(username: str, filepath: str):
    path = Path(filepath)
    if not path.exists():
        print(f"Error: File '{filepath}' was not found.")
        return

    data = path.read_bytes()
    nonce = generate_nonce()

    signature = sign_data(username, data, nonce)

    if not is_nonce_valid(nonce):
        return

    ciphertext, key, nonce_aes = encrypt_file(data)
    (STORAGE_DIR / f"{path.name}.enc").write_bytes(ciphertext)
    metadata = {
        "signature": base64.b64encode(signature).decode("utf-8"),
        "key": base64.b64encode(key).decode("utf-8"),
        "nonce_aes": base64.b64encode(nonce_aes).decode("utf-8"),
        "nonce": nonce,
        "uploader": username,
        "original_filename": path.name,
        "timestamp": datetime.now().isoformat(),
    }
    (STORAGE_DIR / f"{path.name}.json").write_text(json.dumps(metadata, indent=2))
    print(f"\nSuccess: File stored successfully.")



def download_file(username: str, filename: str):
    enc_path = STORAGE_DIR / f"{filename}.enc"
    json_path = STORAGE_DIR / f"{filename}.json"

    if not enc_path.exists() or not json_path.exists():
        print("Error: Required files were not found.")
        return

    metadata = json.loads(json_path.read_text())
    ciphertext = enc_path.read_bytes()
    key = base64.b64decode(metadata["key"])
    nonce_aes = base64.b64decode(metadata["nonce_aes"])
    signature = base64.b64decode(metadata["signature"])

    try:
        plaintext = decrypt_file(ciphertext, key, nonce_aes)

        if verify_signature(
            metadata["uploader"], plaintext, metadata["nonce"], signature
        ):
            out_name = f"downloaded_{metadata['original_filename']}"
            Path(out_name).write_bytes(plaintext)
            print(f"\n[SUCCESS] Signature verified. Saved as '{out_name}'.")
        else:
            print("\n[WARNING] Digital signature verification failed!")
    except Exception as e:
        print(f"Error during recovery: {e}")



def show_menu():
    print("\n" + "=" * 48)
    print("       Secure File Storage - Assignment 2")
    print("=" * 48)
    print(" 1. Register (with OTP)")
    print(" 2. Login")
    print(" 3. Upload File")
    print(" 4. Download File")
    print(" 0. Exit")
    print("=" * 48)



def main():
    initialize_system()
    logged_in_user = None

    while True:
        show_menu()
        if logged_in_user:
            print(f" [Logged in as: {logged_in_user}]")

        c = input("Select option: ").strip()

        if c == "1":
            u = input("Username: ").strip()
            o = input("Enter the OTP you received: ").strip()
            p = input("Password: ").strip()
            register_user(u, o, p)

        elif c == "2":
            u = input("Username: ").strip()
            p = input("Password: ").strip()
            if authenticate_user(u, p):
                logged_in_user = u
                print(f"\nLogin successful!")

        elif c == "3":
            if not logged_in_user:
                print("You must log in first.")
                continue
            path = input("File path for upload: ").strip()
            upload_file(logged_in_user, path)

        elif c == "4":
            if not logged_in_user:
                print("You must log in first.")
                continue
            fname = input("Filename (e.g. test.txt): ").strip()
            download_file(logged_in_user, fname)

        elif c == "9":
            u = input("Username for OTP issuance: ").strip()
            admin_issue_otp(u)

        elif c == "0":
            print("Exiting the system.")
            break
        else:
            print("Invalid option.")


if __name__ == "__main__":
    main()
```
