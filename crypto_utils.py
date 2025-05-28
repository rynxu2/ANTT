import os
import hashlib
import base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
import secrets

def generate_rsa_keypair(key_size=4096):
    """Generate RSA key pair and return PEM encoded strings (4096 bits for better security)"""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )
    
    public_key = private_key.public_key()
    
    # Serialize to PEM format
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')
    
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')
    
    return public_pem, private_pem

def load_public_key_from_pem(pem_data):
    """Load RSA public key from PEM string"""
    return serialization.load_pem_public_key(
        pem_data.encode('utf-8'),
        backend=default_backend()
    )

def load_private_key_from_pem(pem_data):
    """Load RSA private key from PEM string"""
    return serialization.load_pem_private_key(
        pem_data.encode('utf-8'),
        password=None,
        backend=default_backend()
    )

def encrypt_with_public_key(data, public_key_pem):
    """Encrypt data with RSA public key using OAEP padding"""
    public_key = load_public_key_from_pem(public_key_pem)
    
    # Ensure data is bytes
    if isinstance(data, str):
        data = data.encode('utf-8')
    elif not isinstance(data, bytes):
        raise ValueError("Data must be either string or bytes")
    
    try:
        print(f"Data length to encrypt: {len(data)} bytes")
        print(f"Data to encrypt (hex): {data.hex()}")
        
        ciphertext = public_key.encrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),  # Changed to SHA256
                algorithm=hashes.SHA256(),  # Changed to SHA256
                label=None
            )
        )
        
        return ciphertext
    except ValueError as e:
        print(f"Encryption error: {str(e)}")
        raise

def decrypt_with_private_key(ciphertext, private_key_pem):
    """Decrypt data with RSA private key using OAEP padding"""
    private_key = load_private_key_from_pem(private_key_pem)
    
    try:
        print(f"Data length to decrypt: {len(ciphertext)} bytes")
        print(f"Data to decrypt (hex): {ciphertext.hex()}")
        
        plaintext = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),  # Changed to match encryption
                algorithm=hashes.SHA256(),  # Changed to match encryption
                label=None
            )
        )
        
        print(f"Decrypted data length: {len(plaintext)} bytes")
        print(f"Decrypted data (hex): {plaintext.hex()}")
        return plaintext
        
    except ValueError as e:
        print(f"Decryption error: {str(e)}")
        raise

def sign_data(data, private_key_pem):
    """Sign data with RSA private key using PSS padding and SHA-512"""
    private_key = load_private_key_from_pem(private_key_pem)
    
    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA512()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA512()
    )
    
    return signature

def verify_signature(data, signature, public_key_pem):
    """Verify signature with RSA public key"""
    try:
        public_key = load_public_key_from_pem(public_key_pem)
        
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA512()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA512()
        )
        return True
    except InvalidSignature:
        return False

def generate_session_key():
    """Generate a random 256-bit AES key"""
    return secrets.token_bytes(32)  # 256 bits

def encrypt_file_aes(file_data, key, iv=None):
    """Encrypt file data using AES-256-CBC"""
    if iv is None:
        iv = secrets.token_bytes(16)  # 128-bit IV for AES
    
    # Pad the data to be multiple of 16 bytes (PKCS7 padding)
    padding_length = 16 - (len(file_data) % 16)
    padded_data = file_data + bytes([padding_length]) * padding_length
    
    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend()
    )
    
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    
    return ciphertext, iv

def decrypt_file_aes(ciphertext, key, iv):
    """Decrypt file data using AES-256-CBC"""
    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend()
    )
    
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    
    # Remove PKCS7 padding
    padding_length = padded_data[-1]
    file_data = padded_data[:-padding_length]
    
    return file_data

def hash_file(file_data):
    """Generate SHA-512 hash of file data"""
    return hashlib.sha512(file_data).hexdigest()

def hash_data_with_salt(data, salt):
    """Generate SHA-512 hash with salt"""
    return hashlib.sha512(salt + data).hexdigest()
