from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.backends import default_backend
import os
import base64

# Generate a new key (32 bytes for AES-256)
def generate_key():
    return os.urandom(32)

# Generate a new salt (16 bytes)
def generate_salt():
    return os.urandom(16)

# Save key and salt to files
def save_key_and_salt(key, salt):
    with open('encryption_key.key', 'wb') as key_file:
        key_file.write(key)
    with open('salt.salt', 'wb') as salt_file:
        salt_file.write(salt)

# Generate and save key and salt
key = generate_key()
salt = generate_salt()
save_key_and_salt(key, salt)

print(f"Generated Key: {base64.urlsafe_b64encode(key).decode()}")
print(f"Generated Salt: {base64.urlsafe_b64encode(salt).decode()}")
