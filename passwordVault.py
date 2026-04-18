#!/usr/bin/python3

'''
Secure password vault with salting.
Written by Alayna Ferdarko on 18 April, 2026.
This uses Argon2 and AES-GCM for encryption
'''
import os
import json
import time
import hmac
import hashlib
import secrets
import string
import getpass

from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# =========================
# CONFIGURATION
# =========================

VAULT_FILE = "vault.dat"
FAILED_ATTEMPTS = 0
LOCKOUT_LIMIT = 3
LOCKOUT_TIME = 30


# =========================
# CRYPTOGRAPHIC LAYER
# =========================

def derive_key(password: str, salt: bytes) -> bytes:
    #Argon2id key derivation (32-byte key).
    return hash_secret_raw(
        secret=password.encode(),
        salt=salt,
        time_cost=3,
        memory_cost=65536,
        parallelism=2,
        hash_len=32,
        type=Type.ID
    )


def derive_hmac_key(key: bytes) -> bytes:
    return hashlib.sha256(key + b"hmac").digest()


def encrypt(data: bytes, key: bytes) -> dict:
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, data, None)

    return {
        "nonce": nonce.hex(),
        "ciphertext": ciphertext.hex()
    }


def decrypt(payload: dict, key: bytes) -> bytes:
    aesgcm = AESGCM(key)

    nonce = bytes.fromhex(payload["nonce"])
    ciphertext = bytes.fromhex(payload["ciphertext"])

    return aesgcm.decrypt(nonce, ciphertext, None)


def generate_hmac(data: bytes, key: bytes) -> str:
    return hmac.new(key, data, hashlib.sha256).hexdigest()


def verify_hmac(data: bytes, signature: str, key: bytes) -> bool:
    return hmac.compare_digest(
        generate_hmac(data, key),
        signature
    )


# =========================
# PASSWORD GENERATION
# =========================

def generate_password(length: int = 16) -> str:
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_"
    return ''.join(secrets.choice(alphabet) for _ in range(length))


# =========================
# VAULT CORE
# =========================

def create_vault(password: str):
    salt = os.urandom(16)
    key = derive_key(password, salt)

    vault_data = {"entries": []}
    plaintext = json.dumps(vault_data).encode()

    encrypted = encrypt(plaintext, key)
    hmac_key = derive_hmac_key(key)
    mac = generate_hmac(plaintext, hmac_key)

    vault = {
        "salt": salt.hex(),
        "vault": encrypted,
        "hmac": mac,
        "version": 1
    }

    with open(VAULT_FILE, "w") as f:
        json.dump(vault, f, indent=2)

    print("Vault created successfully.")


def load_vault(password: str):
    global FAILED_ATTEMPTS

    if not os.path.exists(VAULT_FILE):
        print("No vault found.")
        return None, None, None

    with open(VAULT_FILE, "r") as f:
        vault_file = json.load(f)

    salt = bytes.fromhex(vault_file["salt"])
    key = derive_key(password, salt)
    hmac_key = derive_hmac_key(key)

    decrypted = decrypt(vault_file["vault"], key)

    if not verify_hmac(decrypted, vault_file["hmac"], hmac_key):
        print("Vault integrity check FAILED.")
        return None, None, None

    return json.loads(decrypted.decode()), key, vault_file


def save_vault(vault_data, key, vault_file):
    plaintext = json.dumps(vault_data).encode()

    encrypted = encrypt(plaintext, key)
    hmac_key = derive_hmac_key(key)

    vault_file["vault"] = encrypted
    vault_file["hmac"] = generate_hmac(plaintext, hmac_key)

    with open(VAULT_FILE, "w") as f:
        json.dump(vault_file, f, indent=2)


# =========================
# VAULT OPERATIONS
# =========================

def add_entry(vault_data, service, username, password):
    vault_data["entries"].append({
        "service": service,
        "username": username,
        "password": password
    })


def search(vault_data, service):
    return [
        e for e in vault_data["entries"]
        if e["service"].lower() == service.lower()
    ]


# =========================
# LOCKOUT LOGIC
# =========================

def check_lockout():
    global FAILED_ATTEMPTS

    if FAILED_ATTEMPTS >= LOCKOUT_LIMIT:
        print("Too many failed attempts. You are currently locked out.")
        time.sleep(LOCKOUT_TIME)
        FAILED_ATTEMPTS = 0


# =========================
# UI HELPERS
# =========================

def prompt_master_password():
    return getpass.getpass("Master password: ")


# =========================
# MENU HANDLERS
# =========================

def handle_add(vault_data, key, vault_file):
    service = input("Service: ")
    username = input("Username: ")

    gen = input("Generate password? (y/n): ").lower()

    if gen == "y":
        password = generate_password()
        print(f"Generated password: {password}")
    else:
        password = input("Password: ")

    add_entry(vault_data, service, username, password)
    save_vault(vault_data, key, vault_file)

    print("Entry added.")


def handle_search(vault_data):
    service = input("Service to search: ")
    results = search(vault_data, service)

    if not results:
        print("No results found.")
        return

    for r in results:
        print("\n---")
        print(f"Service: {r['service']}")
        print(f"Username: {r['username']}")
        print(f"Password: {r['password']}")


def handle_list(vault_data):
    if not vault_data["entries"]:
        print("Vault is empty.")
        return

    for i, e in enumerate(vault_data["entries"], 1):
        print(f"\n[{i}] {e['service']}")
        print(f"    Username: {e['username']}")
        print(f"    Password: {e['password']}")


def handle_edit(vault_data, key, vault_file):
    service = input("Service to edit: ")
    matches = search(vault_data, service)

    if not matches:
        print("No match found.")
        return

    entry = matches[0]

    print("Leave blank to keep current value.")

    new_user = input(f"Username ({entry['username']}): ")
    new_pass = input("Password: ")

    if new_user:
        entry["username"] = new_user
    if new_pass:
        entry["password"] = new_pass

    save_vault(vault_data, key, vault_file)
    print("Entry Updated.")


# =========================
# APP FLOW
# =========================

def init_flow():
    print("\n Creating new vault")
    pw = getpass.getpass("Create master password: ")
    confirm = getpass.getpass("Confirm password: ")

    if pw != confirm:
        print("Passwords do not match.")
        return None, None, None

    create_vault(pw)
    return load_vault(pw)


def unlock_flow():
    pw = getpass.getpass("Master password: ")
    return load_vault(pw)


def menu_loop(vault_data, key, vault_file):
    while True:
        print("\n====== VAULT MENU ======")
        print("1) Add entry")
        print("2) Edit entry")
        print("3) Search")
        print("4) List all")
        print("5) Exit")

        choice = input("Select option: ")

        if choice == "1":
            handle_add(vault_data, key, vault_file)
        elif choice == "2":
            handle_edit(vault_data, key, vault_file)
        elif choice == "3":
            handle_search(vault_data)
        elif choice == "4":
            handle_list(vault_data)
        elif choice == "5":
            print("You're logged out.")
            break
        else:
            print("Invalid option.")


def main():
    print("\n Secure Vault \n")

    if not os.path.exists(VAULT_FILE):
        print("No vault detected.")
        vault_data, key, vault_file = init_flow()
    else:
        choice = input("Vault found. Unlock? (y/n): ").lower()

        if choice == "y":
            vault_data, key, vault_file = unlock_flow()
        else:
            vault_data, key, vault_file = init_flow()

    if vault_data is None:
        print("Failed to initialize vault.")
        return

    menu_loop(vault_data, key, vault_file)


# =========================
# ENTRY POINT
# =========================

if __name__ == "__main__":
    main()
