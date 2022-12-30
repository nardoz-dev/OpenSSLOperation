import hashlib
import os
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5

def encrypt_aes_cbc(plaintext, key, iv):
    # pad the plaintext to a multiple of 16 bytes
    plaintext = plaintext + b'\x00' * (16 - len(plaintext) % 16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(plaintext)
    return ciphertext

def decrypt_aes_cbc(ciphertext, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext


def sign_rsa(data, private_key):
    signer = PKCS1_v1_5.new(private_key)
    digest = hashlib.sha256(data).digest()
    signature = signer.sign(digest)
    return signature

def verify_rsa(data, signature, public_key):
    verifier = PKCS1_v1_5.new(public_key)
    digest = hashlib.sha256(data).digest()
    return verifier.verify(digest, signature)

# generate a random 16-byte key and initialization vector for AES-CBC
key = os.urandom(16)
iv = os.urandom(16)

# generate a new RSA key pair
private_key = RSA.generate(2048)
public_key = private_key.publickey()

# encrypt the plaintext using AES-CBC
plaintext = b'Hello, World!'
ciphertext = encrypt_aes_cbc(plaintext, key, iv)

# sign the ciphertext with the private RSA key
signature = sign_rsa(ciphertext, private_key)

# verify the signature with the public RSA key
assert verify_rsa(ciphertext, signature, public_key)

# Simulate a trasmission of the data :  key, iv, ciphertext, and signature to the recipient
transmitted_data = (key, iv, ciphertext, signature)
# Receive the transmitted data
received_key, received_iv, received_ciphertext, received_signature = transmitted_data

# verify the signature with the public RSA key
assert verify_rsa(received_ciphertext, received_signature, public_key)

# decrypt the ciphertext using AES-CBC
decrypted_plaintext = decrypt_aes_cbc(received_ciphertext, received_key, received_iv)

# remove the padding from the decrypted plaintext
decrypted_plaintext = decrypted_plaintext.rstrip(b'\x00')

print(decrypted_plaintext)  # prints "Hello, World!"
