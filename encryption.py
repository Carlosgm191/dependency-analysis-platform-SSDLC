from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import hashlib
import hmac
import os
import json

# ==========================================================
# PASSWORD HASHING
# ==========================================================

SERVER_KEY = b'12345678901234567890123456789012' # Clave secreta del servidor (32 bytes para AES-256)

def hash_password(password):
    salt = os.urandom(16)

    key = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode(),
        salt,
        200000,
        32
    )

    return {
        "algorithm": "pbkdf2_sha256",
        "iterations": 200000,
        "salt": salt.hex(),
        "hash": key.hex()
    }


def verify_password(password, stored_data):
    salt = bytes.fromhex(stored_data['salt'])
    iterations = stored_data['iterations']

    recalculated = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode(),
        salt,
        iterations,
        32
    ).hex()

    return hmac.compare_digest(recalculated, stored_data["hash"])


# ==========================================================
# USER KEY DERIVATION (CLAVE POR USUARIO)
# ==========================================================

def derive_user_key(password: str, salt_hex: str) -> bytes:
    salt = bytes.fromhex(salt_hex)

    return hashlib.pbkdf2_hmac(
        'sha256',
        password.encode(),
        salt,
        200000,
        32
    )


# ==========================================================
# ENCRYPT / DECRYPT
# ==========================================================

def encrypt_data(data: dict, key: bytes) -> dict:
    cipher = AES.new(key, AES.MODE_EAX)

    plaintext = json.dumps(data).encode()
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)

    return {
        "ciphertext": ciphertext.hex(),
        "nonce": cipher.nonce.hex(),
        "tag": tag.hex()
    }


def decrypt_data(enc_data: dict, key: bytes) -> dict:
    cipher = AES.new(
        key,
        AES.MODE_EAX,
        nonce=bytes.fromhex(enc_data["nonce"])
    )

    decrypted = cipher.decrypt_and_verify(
        bytes.fromhex(enc_data["ciphertext"]),
        bytes.fromhex(enc_data["tag"])
    )

    return json.loads(decrypted.decode())


def encrypt_2fa_secret(secret: str):
    return encrypt_data(secret, SERVER_KEY)



def decrypt_2fa_secret(data: dict):
    return decrypt_data(data, SERVER_KEY)