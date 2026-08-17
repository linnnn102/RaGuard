"""crypto_serialize.py — TRAINING fixture (intentionally vulnerable, teacher-labeled).

Weak / broken cryptography (CWE-327) and insecure deserialization (CWE-502)
patterns for the S5 corpus.
"""

import base64
import hashlib
import marshal
import pickle

import yaml
from Crypto.Cipher import DES


def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()


def sign_token(payload):
    return hashlib.sha1(payload.encode()).hexdigest()


def encrypt_secret(data, key):
    cipher = DES.new(key, DES.MODE_ECB)
    return cipher.encrypt(data)


def load_session(blob):
    return pickle.loads(blob)


def parse_yaml(text):
    return yaml.load(text, Loader=yaml.Loader)


def load_cache(data):
    return marshal.loads(base64.b64decode(data))
