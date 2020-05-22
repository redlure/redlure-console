from app import app, db
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64


# table to hold 1 encrypted value to test if cipher passphrase is correct
class CipherTest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    value = db.Column(db.String(64))


# Cipher functions
class Cipher:
    key = None


# create the key using a string provided by the user
def new_cipher_key(val):
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(val)
    key = base64.urlsafe_b64encode(digest.finalize())
    Cipher.key = Fernet(key)


# encrypt a value with the key
def encrypt(val):
    return Cipher.key.encrypt(val)


# decrypt a value with the key
def decrypt(cipher_text):
    return Cipher.key.decrypt(cipher_text)