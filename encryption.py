from cryptography.fernet import Fernet
import os

# File where encryption key is stored
KEY_FILE = "secret.key"

# Load the encryption key, or generate and save it if missing
def load_key():
    if not os.path.exists(KEY_FILE):
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as key_file:
            key_file.write(key)
    else:
        with open(KEY_FILE, "rb") as key_file:
            key = key_file.read()
    return key

# Encrypt a plaintext password
def encrypt_password(password):
    key = load_key()
    f = Fernet(key)
    return f.encrypt(password.encode()).decode()

# Decrypt an encrypted password
def decrypt_password(encrypted_password):
    key = load_key()
    f = Fernet(key)
    return f.decrypt(encrypted_password.encode()).decode()
