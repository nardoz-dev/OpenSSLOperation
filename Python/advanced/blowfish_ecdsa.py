# Import the necessary modules
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.hashes import SHA256
import hashlib
from cryptography.hazmat.backends import default_backend
import base64
from Crypto.Cipher import Blowfish

# Generate a new ECDSA key pair
private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
public_key = private_key.public_key()

# Set the key for Blowfish. This must be kept secret.
key = b'Eight to fifty six byte key'

# The message to be encrypted and signed.
message = b'This is the message to be encrypted and signed.'

# Pad the message to a multiple of 8 bytes so that it can be encrypted.
padding = b' ' * (8 - (len(message) % 8))
message = message + padding

# Compute the hash of the message using SHA256
message_digest = hashlib.sha256(message).digest()

# Sign the message using the private key
signature = private_key.sign(message_digest, ec.ECDSA(SHA256()))

# Encrypt the signed message using Blowfish
cipher = Blowfish.new(key, Blowfish.MODE_ECB)
ciphertext = cipher.encrypt(message)

# Encode the ciphertext as a base64 string for transport
ciphertext_b64 = base64.b64encode(ciphertext)

# Send the encrypted message, the signature, and the public key to the recipient

# The recipient can verify the signature using the public key
if public_key.verify(signature, message_digest, ec.ECDSA(SHA256())):
    print("Signature is valid.")
else:
    print("Signature is not valid.")

# The recipient can decrypt the message using the shared secret key
cipher = Blowfish.new(key, Blowfish.MODE_ECB)

# Decode the base64 ciphertext and decrypt it
plaintext = cipher.decrypt(base64.b64decode(ciphertext_b64)).rstrip()

print(f'Original message: {message}')
print(f'Encrypted message: {ciphertext_b64}')
print(f'Decrypted message: {plaintext}')
