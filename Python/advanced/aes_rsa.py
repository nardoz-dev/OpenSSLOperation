from Cryptodome.Cipher import AES
from Cryptodome.PublicKey import RSA
from Cryptodome.Hash import SHA256
from Cryptodome.Signature import PKCS1_v1_5
from Cryptodome.Util.Padding import pad, unpad

# Generate a new RSA key pair
private_key = RSA.generate(2048)
public_key = private_key.publickey()

# Set the key. This must be kept secret.
key = b'0123456789abcdef'

# The message to be encrypted.
message = b'This is the message to be encrypted and signed.'

# Pad the message to a multiple of 8 bytes so that it can be encrypted.
padded_message = pad(message, AES.block_size)

# Create the cipher object and encrypt the message.
cipher = AES.new(key, AES.MODE_ECB)

# Encrypt the message using the cipher
ciphertext = cipher.encrypt(padded_message)

# Hash the encrypted message
hashed_message = SHA256.new(ciphertext)

# Sign the hashed message using the private key
signature = PKCS1_v1_5.new(private_key).sign(hashed_message)

# Send the encrypted message and signature to the recipient

# The recipient can verify the signature using the public key
if PKCS1_v1_5.new(public_key).verify(hashed_message, signature):
    print("Signature is valid.")
else:
    print("Signature not valid")

# The recipient can decrypt the message using the shared secret key
decryptor = AES.new(key, AES.MODE_ECB)
plaintext_padded = decryptor.decrypt(ciphertext)

# Remove the padding from the plaintext
plaintext = unpad(plaintext_padded, AES.block_size)

print(f'Original message: {message}')
print(f'Encrypted message: {ciphertext}')
print(f'Decrypted message: {plaintext}')
