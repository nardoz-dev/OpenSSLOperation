import base64
import hashlib
import os

from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5

# Generate a new RSA key pair
private_key = RSA.generate(2048)
public_key = private_key.publickey()

# Encrypt the message with AES
def encrypt_aes(message, key):
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CFB, iv)
    return base64.b64encode(iv + cipher.encrypt(message.encode())).decode('utf-8')

# Decrypt the message with AES
def decrypt_aes(encrypted, key):
    encrypted = base64.b64decode(encrypted)
    iv = encrypted[:16]
    cipher = AES.new(key, AES.MODE_CFB, iv)
    return cipher.decrypt(encrypted[16:]).decode('utf-8')

# Sign the message with RSA
def sign_rsa(message, private_key):
    message = message.encode('utf-8')
    hash = hashlib.sha256(message).hexdigest()
    signature = PKCS1_v1_5.new(private_key).sign(hash)
    return base64.b64encode(signature).decode('utf-8')

# Verify the signature with RSA
def verify_rsa(message, signature, public_key):
    message = message.encode('utf-8')
    hash = hashlib.sha256(message).hexdigest()
    signature = base64.b64decode(signature)
    return PKCS1_v1_5.new(public_key).verify(hash, signature)

# Key for encrypting and decrypting the message
key = b'Sixteen byte key'

# Original message
message = 'Hello, World!'

# Encrypt the message
encrypted = encrypt_aes(message, key)
print(f'Encrypted message: {encrypted}')

# Sign the message
signature = sign_rsa(message, private_key)
print(f'Signature: {signature}')

# Send the encrypted message and signature

# Receiver receives the encrypted message and signature

# Verify the signature
is_valid = verify_rsa(message, signature, public_key)
print(f'Signature is valid: {is_valid}')

# Decrypt the message
decrypted = decrypt_aes(encrypted, key)
print(f'Decrypted message: {decrypted}')
