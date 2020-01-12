from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64

class Cipher:
    key = None

def new_cipher_key(val):
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(val)
    key = base64.urlsafe_b64encode(digest.finalize())
    Cipher.key = Fernet(key)


def encrypt(val):
    return Cipher.key.encrypt(val)


def decrypt(cipher_text):
    return Cipher.key.decrypt(cipher_text)