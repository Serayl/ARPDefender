import json
import os

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives import padding as symmetric_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding as asymmetric_padding


# Derive a 256 bit cryptographic key from a password
def derive_key(password, salt):
    binary_password = password.encode()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=500000,
    )
    key = kdf.derive(binary_password)
    return key


# Currently uses AES 256, CBC mode
def encrypt(data, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES256(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    padder = symmetric_padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    return iv, encrypted_data


def decrypt(data, key):
    iv, encrypted_data = data[:16], data[16:]
    cipher = Cipher(algorithms.AES256(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    unpadder = symmetric_padding.PKCS7(128).unpadder()
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
    unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()
    return unpadded_data


# Generate RSA key pair and save it to fixed files. This function uses
# the password to generate an AES key used to encrypt the private key
# at rest.
def generate_keys(password):
    salt = os.urandom(16)
    # Generate RSA key pair
    private_key_generated = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # Serialize the public key to PEM format, which is the usual format for openssl keys (the one we will accept)
    public_key = private_key_generated.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    # Derive a key
    key = derive_key(password, salt)
    # Serialize the private key
    private_key_bytes = private_key_generated.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    # Encrypt the private key
    iv, private_key_encrypted = encrypt(private_key_bytes, key)
    # Save the keys
    with open(os.path.join("data", 'private_key.pem'), 'wb') as private_file:
        private_file.write(iv)
        private_file.write(private_key_encrypted)
    with open(os.path.join("data", 'public_key.pem'), 'wb') as public_file:
        public_file.write(public_key)
    with open(os.path.join("data", 'salt.bin'), 'wb') as salt_file:
        salt_file.write(salt)
    with open(os.path.join("data", 'symmetric.bin'), 'wb') as symmetric_file:
        symmetric_file.write(os.urandom(32))
    return salt, iv, private_key_encrypted, public_key


# Load the private key from the PEM file
def load_private_key(pem_file_path, password):
    with open(os.path.join("data", 'salt.bin'), 'rb') as salt_file:
        salt = salt_file.read()
    with open(pem_file_path, 'rb') as key_file:
        encrypted_data = key_file.read()
        key = derive_key(password, salt)
        try:
            private_key_bytes = decrypt(encrypted_data, key)
            private_key = serialization.load_pem_private_key(private_key_bytes, password=None)
        except Exception as e:
            print("Failed to load private key: invalid password or corrupted file.")
            return b''
    return private_key


# Load the public key from the PEM file
def load_public_key(pem_file_path):
    with open(pem_file_path, 'rb') as key_file:
        public_key = serialization.load_pem_public_key(key_file.read())
    return public_key


# Sign a JSON
def sign_json(private_key, data):
    try:
        json_data = json.dumps(data).encode()
        signature = private_key.sign(
            json_data,
            asymmetric_padding.PSS(
                mgf=asymmetric_padding.MGF1(hashes.SHA256()),
                salt_length=asymmetric_padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
    except Exception as e:
        print("Invalid key or empty data.")
        return ""
    return signature


# Verify signature on a JSON
def verify_signature_json(public_key, signature, data):
    json_data = json.dumps(data).encode()
    try:
        public_key.verify(
            signature,
            json_data,
            asymmetric_padding.PSS(
                mgf=asymmetric_padding.MGF1(hashes.SHA256()),
                salt_length=asymmetric_padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except (InvalidSignature, Exception) as e:
        # Could use e to get a better sense of what went wrong when testing, but
        # we limit the information here.
        if isinstance(e, InvalidSignature):
            print("Invalid signature.")
        return False
