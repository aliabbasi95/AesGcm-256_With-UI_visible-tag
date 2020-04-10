import hashlib
import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import (
    Cipher, algorithms, modes)


def encrypt(passphrase, plaintext, entry_aad):
    salt = os.urandom(8)
    key = hashlib.pbkdf2_hmac("sha256", passphrase.encode("utf8"), salt, 1000)
    iv = os.urandom(12)
    plaintext = plaintext.encode("utf8")
    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv),
        backend=default_backend()
    ).encryptor()

    encryptor.authenticate_additional_data(entry_aad.encode("utf8"))
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    tag = encryptor.tag
    print(tag)
    return (iv, ciphertext, tag, salt)


def decrypt(salt, passphrase, associated_data, iv, ciphertext, tag):
    key = hashlib.pbkdf2_hmac("sha256", passphrase.encode("utf8"), salt, 1000)
    decryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv, tag),
        backend=default_backend()
    ).decryptor()

    decryptor.authenticate_additional_data(associated_data)

    text = decryptor.update(ciphertext) + decryptor.finalize()
    text = text.decode("utf8")
    return (text)
