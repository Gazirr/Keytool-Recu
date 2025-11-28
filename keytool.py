import argparse
import json
import os
import base64
import getpass
import hashlib

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.x509 import NameOID
import cryptography.x509 as x509
from datetime import datetime, timedelta


KEYSTORE_FILE = "keystore.json"


# -----------------------------------------------------------
# Utilidades
# -----------------------------------------------------------

def hash_password(pwd: str) -> str:
    return hashlib.sha256(pwd.encode()).hexdigest()


def load_keystore():
    if not os.path.exists(KEYSTORE_FILE):
        return None
    with open(KEYSTORE_FILE, "r") as f:
        return json.load(f)


def save_keystore(data):
    with open(KEYSTORE_FILE, "w") as f:
        json.dump(data, f, indent=4)


# -----------------------------------------------------------
# Comando --genkey
# -----------------------------------------------------------
def generate_keypair(args):

    keystore = load_keystore()

    # Si no existe, crear nuevo
    if keystore is None:
        print("Creating new keystore...")
        pwd = getpass.getpass("New keystore password: ")
        keystore = {
            "keystore_password_hash": hash_password(pwd),
            "keys": {}
        }
        save_keystore(keystore)

    # Validar contraseña de keystore
    pwd = getpass.getpass("Keystore password: ")
    if hash_password(pwd) != keystore["keystore_password_hash"]:
        print("Invalid keystore password.")
        return

    alias = args.alias

    if alias in keystore["keys"]:
        print("Alias already exists in keystore.")
        return

    # Generar clave RSA
    print("Generating 2048-bit RSA keypair...")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    public_key = private_key.public_key()

    # Convertir a base64 para almacenarlo
    private_bytes = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()
    )
    public_bytes = public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )

    key_pwd = getpass.getpass("Password for this key: ")

    keystore["keys"][alias] = {
        "key_password_hash": hash_password(key_pwd),
        "private_key": base64.b64encode(private_bytes).decode(),
        "public_key": base64.b64encode(public_bytes).decode()
    }

    save_keystore(keystore)
    print(f"Key pair stored under alias '{alias}'.")


# -----------------------------------------------------------
# Comando --certreq
# -----------------------------------------------------------
def generate_csr(args):
    alias = args.alias
    keystore = load_keystore()

    if keystore is None:
        print("Keystore not found.")
        return

    pwd = getpass.getpass("Keystore password: ")
    if hash_password(pwd) != keystore["keystore_password_hash"]:
        print("Invalid keystore password.")
        return

    if alias not in keystore["keys"]:
        print("Alias not found in keystore.")
        return

    key_entry = keystore["keys"][alias]

    key_pwd = getpass.getpass("Password for key: ")
    if hash_password(key_pwd) != key_entry["key_password_hash"]:
        print("Invalid key password.")
        return

    # Recuperar private key
    private_bytes = base64.b64decode(key_entry["private_key"])
    private_key = serialization.load_pem_private_key(
        private_bytes,
        password=None
    )

    # Crear CSR
    print("Generating CSR...")
    name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, args.cn)
    ])

    csr = x509.CertificateSigningRequestBuilder().subject_name(name).sign(
        private_key, hashes.SHA256()
    )

    csr_pem = csr.public_bytes(serialization.Encoding.PEM)

    with open(f"{alias}.csr", "wb") as f:
        f.write(csr_pem)

    print(f"CSR generated → {alias}.csr")


# -----------------------------------------------------------
# Comando --help
# -----------------------------------------------------------
def show_help():
    print("""
Mini-Keytool (Python)

Commands:
  --genkey    Generate keypair and store in keystore
              Example: python3 keytool.py --genkey --alias mykey

  --certreq   Generate CSR from stored key
              Example: python3 keytool.py --certreq --alias mykey --cn "My Name"

  --help      Show this help message
""")


# -----------------------------------------------------------
# MAIN
# -----------------------------------------------------------
if __name__ == "__main__":
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--genkey", action="store_true")
    parser.add_argument("--certreq", action="store_true")
    parser.add_argument("--help", action="store_true")
    parser.add_argument("--alias", type=str, default="mykey")
    parser.add_argument("--cn", type=str, default="Unknown")

    args = parser.parse_args()

    if args.help or (not args.genkey and not args.certreq):
        show_help()
    elif args.genkey:
        generate_keypair(args)
    elif args.certreq:
        generate_csr(args)
